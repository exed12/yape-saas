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
    ALTER TABLE pagos ADD COLUMN IF NOT EXISTS app VARCHAR(10) DEFAULT 'Yape';
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

function parseFecha(f) {
  // Convierte YYYY-MM-DD a DD/MM/YYYY si es necesario
  if (!f) return fechaHoyPeru();
  if (f.includes('-') && f.length === 10) {
    const [y,m,d] = f.split('-');
    return d+'/'+m+'/'+y;
  }
  return f;
}
function fechaHoyPeru() { const d=new Date(new Date().toLocaleString('en-US',{timeZone:'America/Lima'})); return String(d.getDate()).padStart(2,'0')+'/'+String(d.getMonth()+1).padStart(2,'0')+'/'+d.getFullYear(); }
function horaAhoraPeru() { return new Date().toLocaleTimeString('es-PE',{timeZone:'America/Lima',hour:'2-digit',minute:'2-digit'}); }

function extraerDatos(body) {
  const textoCompleto = body.texto||body.monto||body.nombre||'';
  const titulo = body.nombre||'';
  let nombre=null,monto=null,codigo=null,app='Yape';

  // Patrones Yape
  const pYape1=/^(.+?)\s+te\s+envi[oó]\s+un\s+pago\s+por\s+S\/\s*([\d,.]+)/i;
  const pYape2=/Yape!\s+(.+?)\s+te\s+envi[oó]\s+un\s+pago\s+por\s+S\/\s*([\d,.]+)/i;
  // Patrones Plin (Interbank y BBVA)
  const pPlin1=/^(.+?)\s+te\s+ha\s+plineado\s+S\.?\/\s*([\d,.]+)/i;      // Interbank: "NOMBRE te ha plineado S./ 1.00"
  const pPlin2=/^(.+?)\s+te\s+pline[oó]\s+S\/\.?\s*([\d,.]+)/i;           // BBVA: "NOMBRE te plineó S/. 1"
  const pPlin3=/pline[oó]|plineado/i;
  // Monto genérico
  const pMonto=/S\.?\/\s*([\d,.]+)/i;
  // Nombre genérico
  const pNombre=/^(.+?)\s+te\s+ha/i;
  const pNombre2=/^(.+?)\s+te\s+envi/i;
  // Código seguridad
  const pCod=/c[oó]d(?:\.|igo)?\s+de\s+seguridad\s+es:\s*(\d+)/i;

  for (const texto of [textoCompleto,titulo]) {
    if (!texto||texto.includes('[')) continue;

    const mc=texto.match(pCod); if(mc&&!codigo)codigo=mc[1];

    // Detectar Plin (Interbank y BBVA)
    const mPlin1=texto.match(pPlin1);
    if(mPlin1){nombre=nombre||mPlin1[1].trim();monto=monto||parseFloat(mPlin1[2].replace(',','.'));app='Plin';continue;}
    const mPlin2=texto.match(pPlin2);
    if(mPlin2){nombre=nombre||mPlin2[1].trim();monto=monto||parseFloat(mPlin2[2].replace(',','.'));app='Plin';continue;}
    if(texto.match(pPlin3)){app='Plin';}

    // Detectar Yape
    const mYape2=texto.match(pYape2);
    if(mYape2){nombre=nombre||mYape2[1].trim();monto=monto||parseFloat(mYape2[2].replace(',','.'));app='Yape';continue;}
    const mYape1=texto.match(pYape1);
    if(mYape1){nombre=nombre||mYape1[1].trim();monto=monto||parseFloat(mYape1[2].replace(',','.'));app='Yape';continue;}

    // Fallback monto y nombre
    const mM=texto.match(pMonto); if(mM&&!monto)monto=parseFloat(mM[1].replace(',','.'));
    const mN=texto.match(pNombre)||texto.match(pNombre2); if(mN&&!nombre)nombre=mN[1].trim();
  }
  return {nombre:nombre||'Pago recibido',monto:monto||0,codigo:codigo||null,app,textoOriginal:textoCompleto};
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
      const dia = parseFecha(fecha);
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
    const {nombre,monto,codigo,app,textoOriginal}=extraerDatos(req.body);
    const pago={id:Date.now(),usuario_id:r.rows[0].id,nombre,monto,codigo,app:app||'Yape',texto_original:textoOriginal,hora:horaAhoraPeru(),fecha:fechaHoyPeru(),ts:ahora};
    await pool.query(
      'INSERT INTO pagos(id,usuario_id,nombre,monto,codigo,app,texto_original,hora,fecha,ts) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)',
      [pago.id,pago.usuario_id,pago.nombre,pago.monto,pago.codigo,pago.app,pago.texto_original,pago.hora,pago.fecha,pago.ts]
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
    if(periodo==='dia'){const dia=parseFecha(fecha);query='SELECT * FROM pagos WHERE usuario_id=$1 AND fecha=$2 ORDER BY ts DESC';params=[req.user.id,dia];}
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
