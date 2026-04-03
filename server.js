// Yape Monitor SaaS v3 - Admin panel completo
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
const ADMIN_EMAIL = (process.env.ADMIN_EMAIL || '').toLowerCase();

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false
});

async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS usuarios (
      id SERIAL PRIMARY KEY,
      nombre_negocio VARCHAR(100) NOT NULL,
      email VARCHAR(150) UNIQUE NOT NULL,
      password_hash VARCHAR(255) NOT NULL,
      token VARCHAR(100) UNIQUE NOT NULL,
      rol VARCHAR(20) DEFAULT 'usuario',
      plan VARCHAR(20) DEFAULT 'basico',
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

  if (ADMIN_EMAIL) {
    const exists = await pool.query('SELECT id FROM usuarios WHERE email=$1', [ADMIN_EMAIL]);
    if (!exists.rows[0]) {
      const hash = await bcrypt.hash(process.env.ADMIN_PASSWORD || 'admin123', 10);
      const token = uuidv4().replace(/-/g,'');
      await pool.query(
        'INSERT INTO usuarios (email,password_hash,nombre_negocio,token,rol) VALUES ($1,$2,$3,$4,$5)',
        [ADMIN_EMAIL, hash, 'Administrador', token, 'admin']
      );
      console.log('Admin creado:', ADMIN_EMAIL);
    }
  }
  console.log('Base de datos lista');
}

function fechaHoyPeru() { return new Date().toLocaleDateString('es-PE',{timeZone:'America/Lima'}); }
function horaAhoraPeru() { return new Date().toLocaleTimeString('es-PE',{timeZone:'America/Lima',hour:'2-digit',minute:'2-digit'}); }

function extraerDatos(body) {
  const textoCompleto = body.texto||body.monto||body.nombre||'';
  const titulo = body.nombre||'';
  let nombre=null,monto=null,codigo=null;
  const p1=/^(.+?)\s+te\s+envi[oó]\s+un\s+pago\s+por\s+S\/\s*([\d,.]+)/i;
  const p2=/Yape!\s+(.+?)\s+te\s+envi[oó]\s+un\s+pago\s+por\s+S\/\s*([\d,.]+)/i;
  const p3=/S\/\s*([\d,.]+)/i;
  const p4=/^(.+?)\s+te\s+envi/i;
  const pCod=/c[oó]d(?:\.|igo)?\s+de\s+seguridad\s+es:\s*(\d+)/i;
  for (const texto of [textoCompleto,titulo]) {
    if (!texto||texto.includes('[')) continue;
    const mc=texto.match(pCod); if(mc&&!codigo)codigo=mc[1];
    const m2=texto.match(p2); if(m2){nombre=nombre||m2[1].trim();monto=monto||parseFloat(m2[2].replace(',','.'));continue;}
    const m1=texto.match(p1); if(m1){nombre=nombre||m1[1].trim();monto=monto||parseFloat(m1[2].replace(',','.'));continue;}
    const m3=texto.match(p3); if(m3&&!monto)monto=parseFloat(m3[1].replace(',','.'));
    const m4=texto.match(p4); if(m4&&!nombre)nombre=m4[1].trim();
  }
  return {nombre:nombre||'Pago recibido',monto:monto||0,codigo:codigo||null,textoOriginal:textoCompleto};
}

function authMiddleware(req,res,next) {
  const token=req.cookies.token||req.headers.authorization?.replace('Bearer ','');
  if(!token) return res.status(401).json({error:'No autenticado'});
  try{req.user=jwt.verify(token,JWT_SECRET);next();}
  catch{res.status(401).json({error:'Token inválido'});}
}

function adminMiddleware(req,res,next) {
  if(req.user?.rol!=='admin') return res.status(403).json({error:'Acceso denegado'});
  next();
}

// ── AUTH ──────────────────────────────────────────────────────────────────────
app.post('/api/login', async (req,res) => {
  const {email,password}=req.body;
  if(!email||!password) return res.status(400).json({error:'Campos requeridos'});
  try {
    const r=await pool.query('SELECT * FROM usuarios WHERE email=$1 AND activo=true',[email.toLowerCase()]);
    const user=r.rows[0];
    if(!user||!(await bcrypt.compare(password,user.password_hash)))
      return res.status(401).json({error:'Credenciales incorrectas'});
    const tk=jwt.sign({id:user.id,email:user.email,nombre_negocio:user.nombre_negocio,rol:user.rol},JWT_SECRET,{expiresIn:'30d'});
    res.cookie('token',tk,{httpOnly:true,maxAge:30*24*60*60*1000});
    res.json({ok:true,rol:user.rol});
  } catch(e){console.error(e);res.status(500).json({error:'Error del servidor'});}
});

app.post('/api/logout',(req,res)=>{res.clearCookie('token');res.json({ok:true});});

app.get('/api/me',authMiddleware,async(req,res)=>{
  try {
    const r=await pool.query('SELECT id,email,nombre_negocio,token,plan,rol FROM usuarios WHERE id=$1',[req.user.id]);
    res.json(r.rows[0]);
  } catch(e){res.status(500).json({error:'Error'});}
});

app.put('/api/me',authMiddleware,async(req,res)=>{
  const {nombre_negocio}=req.body;
  if(!nombre_negocio) return res.status(400).json({error:'Nombre requerido'});
  try{await pool.query('UPDATE usuarios SET nombre_negocio=$1 WHERE id=$2',[nombre_negocio,req.user.id]);res.json({ok:true});}
  catch(e){res.status(500).json({error:'Error'});}
});

// ── ADMIN ─────────────────────────────────────────────────────────────────────
app.get('/api/admin/stats',authMiddleware,adminMiddleware,async(req,res)=>{
  try {
    const usuarios=await pool.query("SELECT COUNT(*) FROM usuarios WHERE rol!='admin'");
    const activos=await pool.query("SELECT COUNT(*) FROM usuarios WHERE rol!='admin' AND activo=true");
    const pagosHoy=await pool.query('SELECT COUNT(*),COALESCE(SUM(monto),0) as total FROM pagos WHERE fecha=$1',[fechaHoyPeru()]);
    const pagosMes=await pool.query("SELECT COUNT(*),COALESCE(SUM(monto),0) as total FROM pagos WHERE ts>=date_trunc('month',NOW())");
    const pagosTotal=await pool.query('SELECT COUNT(*),COALESCE(SUM(monto),0) as total FROM pagos');
    res.json({
      usuarios:parseInt(usuarios.rows[0].count),
      activos:parseInt(activos.rows[0].count),
      pagosHoy:{cantidad:parseInt(pagosHoy.rows[0].count),total:parseFloat(pagosHoy.rows[0].total)},
      pagosMes:{cantidad:parseInt(pagosMes.rows[0].count),total:parseFloat(pagosMes.rows[0].total)},
      pagosTotal:{cantidad:parseInt(pagosTotal.rows[0].count),total:parseFloat(pagosTotal.rows[0].total)}
    });
  } catch(e){console.error(e);res.status(500).json({error:'Error'});}
});

app.get('/api/admin/usuarios',authMiddleware,adminMiddleware,async(req,res)=>{
  try {
    const r=await pool.query(`
      SELECT u.id,u.nombre_negocio,u.email,u.plan,u.activo,u.created_at,u.token,
        COUNT(p.id) as total_pagos,
        COALESCE(SUM(p.monto),0) as total_monto,
        MAX(p.ts) as ultimo_pago
      FROM usuarios u
      LEFT JOIN pagos p ON p.usuario_id=u.id
      WHERE u.rol!='admin'
      GROUP BY u.id ORDER BY u.created_at DESC
    `);
    res.json(r.rows);
  } catch(e){console.error(e);res.status(500).json({error:'Error'});}
});

app.post('/api/admin/usuarios',authMiddleware,adminMiddleware,async(req,res)=>{
  const {email,password,nombre_negocio,plan}=req.body;
  if(!email||!password||!nombre_negocio) return res.status(400).json({error:'Campos requeridos'});
  if(password.length<6) return res.status(400).json({error:'Contraseña mínimo 6 caracteres'});
  try {
    const hash=await bcrypt.hash(password,10);
    const token=uuidv4().replace(/-/g,'');
    const r=await pool.query(
      'INSERT INTO usuarios(email,password_hash,nombre_negocio,token,plan) VALUES($1,$2,$3,$4,$5) RETURNING id,email,nombre_negocio,token,plan',
      [email.toLowerCase(),hash,nombre_negocio,token,plan||'basico']
    );
    res.json({ok:true,usuario:r.rows[0]});
  } catch(e){
    if(e.code==='23505') return res.status(400).json({error:'Email ya registrado'});
    res.status(500).json({error:'Error del servidor'});
  }
});

app.put('/api/admin/usuarios/:id',authMiddleware,adminMiddleware,async(req,res)=>{
  const {activo,plan,nombre_negocio,password}=req.body;
  try {
    if(typeof activo==='boolean') await pool.query('UPDATE usuarios SET activo=$1 WHERE id=$2',[activo,req.params.id]);
    if(plan) await pool.query('UPDATE usuarios SET plan=$1 WHERE id=$2',[plan,req.params.id]);
    if(nombre_negocio) await pool.query('UPDATE usuarios SET nombre_negocio=$1 WHERE id=$2',[nombre_negocio,req.params.id]);
    if(password&&password.length>=6){const h=await bcrypt.hash(password,10);await pool.query('UPDATE usuarios SET password_hash=$1 WHERE id=$2',[h,req.params.id]);}
    res.json({ok:true});
  } catch(e){res.status(500).json({error:'Error'});}
});

app.delete('/api/admin/usuarios/:id',authMiddleware,adminMiddleware,async(req,res)=>{
  try {
    await pool.query('DELETE FROM pagos WHERE usuario_id=$1',[req.params.id]);
    await pool.query('DELETE FROM usuarios WHERE id=$1',[req.params.id]);
    res.json({ok:true});
  } catch(e){res.status(500).json({error:'Error'});}
});

// Pagos de un usuario con filtro de periodo
app.get('/api/admin/usuarios/:id/pagos',authMiddleware,adminMiddleware,async(req,res)=>{
  const {periodo,fecha} = req.query;
  try {
    let query, params;
    const hoy = fechaHoyPeru();
    if (!periodo || periodo==='dia') {
      const dia = fecha || hoy;
      query = 'SELECT * FROM pagos WHERE usuario_id=$1 AND fecha=$2 ORDER BY ts DESC';
      params = [req.params.id, dia];
    } else if (periodo==='semana') {
      query = "SELECT * FROM pagos WHERE usuario_id=$1 AND ts>=NOW()-INTERVAL '7 days' ORDER BY ts DESC";
      params = [req.params.id];
    } else if (periodo==='mes') {
      const mes = fecha || new Date().toISOString().slice(0,7);
      query = "SELECT * FROM pagos WHERE usuario_id=$1 AND TO_CHAR(ts,'YYYY-MM')=$2 ORDER BY ts DESC";
      params = [req.params.id, mes];
    } else if (periodo==='anio') {
      const anio = fecha || String(new Date().getFullYear());
      query = "SELECT * FROM pagos WHERE usuario_id=$1 AND TO_CHAR(ts,'YYYY')=$2 ORDER BY ts DESC";
      params = [req.params.id, anio];
    } else {
      query = 'SELECT * FROM pagos WHERE usuario_id=$1 ORDER BY ts DESC LIMIT 500';
      params = [req.params.id];
    }
    const r = await pool.query(query, params);
    const pagos = r.rows;
    const total = pagos.reduce((s,p)=>s+parseFloat(p.monto||0),0);
    const porDia = {};
    pagos.forEach(p=>{porDia[p.fecha]=(porDia[p.fecha]||0)+parseFloat(p.monto||0);});
    res.json({pagos, total:parseFloat(total.toFixed(2)), cantidad:pagos.length, porDia});
  } catch(e){console.error(e);res.status(500).json({error:'Error'});}
});

// ── YAPE WEBHOOK ──────────────────────────────────────────────────────────────
app.post('/yape/:token',async(req,res)=>{
  try {
    const r=await pool.query('SELECT id FROM usuarios WHERE token=$1 AND activo=true',[req.params.token]);
    if(!r.rows[0]) return res.status(404).json({error:'Token inválido'});
    const {nombre,monto,codigo,textoOriginal}=extraerDatos(req.body);
    const ahora=new Date();
    const pago={id:Date.now(),usuario_id:r.rows[0].id,nombre,monto,codigo,texto_original:textoOriginal,hora:horaAhoraPeru(),fecha:fechaHoyPeru(),ts:ahora};
    await pool.query(
      'INSERT INTO pagos(id,usuario_id,nombre,monto,codigo,texto_original,hora,fecha,ts) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)',
      [pago.id,pago.usuario_id,pago.nombre,pago.monto,pago.codigo,pago.texto_original,pago.hora,pago.fecha,pago.ts]
    );
    res.json({ok:true});
  } catch(e){console.error(e);res.status(500).json({error:'Error'});}
});

// ── PAGOS API ─────────────────────────────────────────────────────────────────
app.get('/api/pagos',authMiddleware,async(req,res)=>{
  try {
    const r=await pool.query('SELECT * FROM pagos WHERE usuario_id=$1 AND fecha=$2 ORDER BY ts DESC',[req.user.id,fechaHoyPeru()]);
    res.json(r.rows);
  } catch(e){res.status(500).json({error:'Error'});}
});

app.get('/api/reporte',authMiddleware,async(req,res)=>{
  const{periodo,fecha}=req.query;
  try {
    let query,params;
    if(periodo==='dia'){const dia=fecha||fechaHoyPeru();query='SELECT * FROM pagos WHERE usuario_id=$1 AND fecha=$2 ORDER BY ts DESC';params=[req.user.id,dia];}
    else if(periodo==='semana'){query="SELECT * FROM pagos WHERE usuario_id=$1 AND ts>=NOW()-INTERVAL '7 days' ORDER BY ts DESC";params=[req.user.id];}
    else if(periodo==='mes'){const mes=fecha||new Date().toISOString().slice(0,7);query="SELECT * FROM pagos WHERE usuario_id=$1 AND TO_CHAR(ts,'YYYY-MM')=$2 ORDER BY ts DESC";params=[req.user.id,mes];}
    else if(periodo==='anio'){const anio=fecha||String(new Date().getFullYear());query="SELECT * FROM pagos WHERE usuario_id=$1 AND TO_CHAR(ts,'YYYY')=$2 ORDER BY ts DESC";params=[req.user.id,anio];}
    else{query='SELECT * FROM pagos WHERE usuario_id=$1 ORDER BY ts DESC';params=[req.user.id];}
    const r=await pool.query(query,params);
    const pagos=r.rows,total=pagos.reduce((s,p)=>s+parseFloat(p.monto||0),0),porDia={};
    pagos.forEach(p=>{porDia[p.fecha]=(porDia[p.fecha]||0)+parseFloat(p.monto||0);});
    res.json({pagos,total:parseFloat(total.toFixed(2)),cantidad:pagos.length,porDia});
  } catch(e){console.error(e);res.status(500).json({error:'Error'});}
});

// ── RUTAS HTML ────────────────────────────────────────────────────────────────
app.get('/dashboard',(req,res)=>res.sendFile(path.join(__dirname,'public','dashboard.html')));
app.get('/reportes',(req,res)=>res.sendFile(path.join(__dirname,'public','reporte.html')));
app.get('/admin',(req,res)=>res.sendFile(path.join(__dirname,'public','admin.html')));
app.get('/',(req,res)=>res.sendFile(path.join(__dirname,'public','login.html')));
app.get('/ping',(req,res)=>res.send('ok'));

const PORT=process.env.PORT||3000;
initDB().then(()=>{app.listen(PORT,()=>console.log(`Yape SaaS v3 activo en puerto ${PORT}`));}).catch(e=>{console.error('Error DB:',e);process.exit(1);});
