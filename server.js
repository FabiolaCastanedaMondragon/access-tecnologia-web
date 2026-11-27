const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
const path = require('path');
const multer = require('multer');
const fs = require('fs');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const { OAuth2Client } = require('google-auth-library');
const helmet = require('helmet');
const compression = require('compression');

require('dotenv').config();

const app = express();

// Configuración de Helmet para permitir imágenes y CDNs externos
app.use(helmet({
    contentSecurityPolicy: false,
    crossOriginEmbedderPolicy: false,
    crossOriginOpenerPolicy: false,
    crossOriginResourcePolicy: { policy: 'cross-origin' }
}));
app.use(compression());
app.use(cors());
app.use(express.json());

app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// ============================================================
// === CONFIGURACIÓN DE SEGURIDAD ===
// ============================================================
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
    console.error('❌ ERROR CRÍTICO: JWT_SECRET no está configurado en el entorno o .env');
    console.error('   Ejecuta: node -e "console.log(require(\'crypto\').randomBytes(64).toString(\'hex\'))"');
    process.exit(1);
}
const JWT_EXPIRES = '7d';
const SALT_ROUNDS = 10;

console.log('🔐 Servidor con JWT + bcrypt + rate limiting');

const client = new OAuth2Client('62107681583-ebfckf4iuq0ocbgont2mg4votqp0k97i.apps.googleusercontent.com');

// ============================================================
// === BASE DE DATOS (RAILWAY + RESPALDO LOCAL) ===
// ============================================================
const db = mysql.createConnection({
    host: process.env.MYSQLHOST || process.env.DB_HOST || 'localhost',
    user: process.env.MYSQLUSER || process.env.DB_USER || 'root',
    password: process.env.MYSQLPASSWORD ?? process.env.DB_PASSWORD ?? '',
    database: process.env.MYSQLDATABASE || process.env.DB_NAME || 'access_tecnologia',
    port: Number(process.env.MYSQLPORT || process.env.DB_PORT || 3307)
});

db.connect(err => {
    if (err) {
        console.error('❌ Error al conectar a MySQL:', err);
    } else {
        const bdActiva = process.env.MYSQLDATABASE || process.env.DB_NAME || 'access_tecnologia';
        console.log(`✅ Conectado a la BD ${bdActiva}`);
    }
});

// ============================================================
// === MULTER ===
// ============================================================
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });

const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, uploadDir),
    filename: (req, file, cb) => {
        const ext = path.extname(file.originalname).toLowerCase();
        cb(null, `img_${Date.now()}_${Math.round(Math.random() * 1E6)}${ext}`);
    }
});

const fileFilter = (req, file, cb) => {
    const tipos = /jpeg|jpg|png|gif|webp|svg/;
    const extValida = tipos.test(path.extname(file.originalname).toLowerCase());
    const mimeValido = tipos.test(file.mimetype);
    if (extValida && mimeValido) cb(null, true);
    else cb(new Error('Solo imágenes (jpg, png, gif, webp, svg)'));
};

const upload = multer({ storage, fileFilter, limits: { fileSize: 5 * 1024 * 1024 } });

// ============================================================
// === MIDDLEWARES DE SEGURIDAD ===
// ============================================================
function verificarToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'No autenticado. Inicia sesión.' });
    }

    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) {
            return res.status(401).json({ error: 'Token inválido o expirado.' });
        }

        db.query(
            'SELECT id, nombre, email, rol, token_version FROM usuarios WHERE id = ? LIMIT 1',
            [decoded.id],
            (dbErr, results) => {
                if (dbErr) {
                    console.error('❌ Error al verificar sesión en BD:', dbErr);
                    return res.status(500).json({ error: 'Error del servidor' });
                }

                if (results.length === 0) {
                    return res.status(401).json({ error: 'Usuario no encontrado.' });
                }

                const usuarioBD = results[0];
                const versionToken = decoded.token_version ?? 1;
                const versionBD = usuarioBD.token_version ?? 1;

                if (versionToken !== versionBD) {
                    return res.status(401).json({
                        code: 'SESSION_INVALIDATED',
                        error: 'Tu rol o cuenta fue modificada. Inicia sesión nuevamente.'
                    });
                }

                req.usuario = {
                    id: usuarioBD.id,
                    email: usuarioBD.email,
                    rol: usuarioBD.rol || 'vendedor',
                    nombre: usuarioBD.nombre,
                    token_version: versionBD
                };
                next();
            }
        );
    });
}

function soloAdmin(req, res, next) {
    if (!req.usuario || req.usuario.rol !== 'admin') {
        return res.status(403).json({ error: 'Solo administradores' });
    }
    next();
}

function adminOVendedor(req, res, next) {
    if (!req.usuario || !['admin', 'vendedor'].includes(req.usuario.rol)) {
        return res.status(403).json({ error: 'Solo administradores o vendedores' });
    }
    next();
}

// ============================================================
// === RATE LIMITING ===
// ============================================================
const loginLimiter = rateLimit({
    windowMs: 5 * 60 * 1000,
    max: 3,
    message: { success: false, error: 'Demasiados intentos fallidos. Por seguridad, tu cuenta ha sido bloqueada temporalmente por 5 minutos.' },
    standardHeaders: true,
    legacyHeaders: false,
    skipSuccessfulRequests: true
});

const registerLimiter = rateLimit({
    windowMs: 60 * 60 * 1000,
    max: 3,
    message: { success: false, error: 'Demasiados registros. Intenta más tarde.' }
});

const globalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 600,
    message: { error: 'Demasiadas peticiones. Espera un momento.' }
});

app.use('/api/', globalLimiter);

// ============================================================
// === AUDITORÍA ===
// ============================================================
function registrarAuditoria(tabla, registro_id, accion, usuario, datos_anteriores = null, datos_nuevos = null) {
    const query = `INSERT INTO auditoria (tabla, registro_id, accion, usuario, datos_anteriores, datos_nuevos, fecha) VALUES (?, ?, ?, ?, ?, ?, NOW())`;
    db.query(query, [
        tabla || 'sistema',
        registro_id || 0,
        accion,
        usuario || 'Sistema',
        datos_anteriores ? JSON.stringify(datos_anteriores) : null,
        datos_nuevos ? JSON.stringify(datos_nuevos) : null
    ], (err) => {
        if (err) console.error('❌ Error auditoría:', err);
    });
}

function obtenerDiferencias(anterior, nuevo) {
    const cambiosAnteriores = {};
    const cambiosNuevos = {};
    for (const key in nuevo) {
        if (nuevo[key] !== undefined && String(anterior[key]) !== String(nuevo[key])) {
            cambiosAnteriores[key] = anterior[key];
            cambiosNuevos[key] = nuevo[key];
        }
    }
    return {
        anteriores: Object.keys(cambiosAnteriores).length > 0 ? cambiosAnteriores : null,
        nuevos: Object.keys(cambiosNuevos).length > 0 ? cambiosNuevos : null
    };
}

// ============================================================
// === RUTAS DE PÁGINAS (HTML) ===
// ============================================================
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'views', 'index.html')));

app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'views', 'login.html')));
app.get('/register', (req, res) => res.redirect('/login.html'));
app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'views', 'admin.html')));
app.get('/catalogo', (req, res) => res.sendFile(path.join(__dirname, 'views', 'catalogo.html')));
app.get('/cotizar', (req, res) => res.sendFile(path.join(__dirname, 'views', 'cotizadora.html')));
app.get('/servicio', (req, res) => res.sendFile(path.join(__dirname, 'views', 'servicio.html')));

app.get('/index.html', (req, res) => res.sendFile(path.join(__dirname, 'views', 'index.html')));
app.get('/login.html', (req, res) => res.sendFile(path.join(__dirname, 'views', 'login.html')));
app.get('/register.html', (req, res) => res.redirect('/login.html'));
app.get('/admin.html', (req, res) => res.sendFile(path.join(__dirname, 'views', 'admin.html')));
app.get('/catalogo.html', (req, res) => res.sendFile(path.join(__dirname, 'views', 'catalogo.html')));
app.get('/cotizadora.html', (req, res) => res.sendFile(path.join(__dirname, 'views', 'cotizadora.html')));
app.get('/servicio.html', (req, res) => res.sendFile(path.join(__dirname, 'views', 'servicio.html')));

// ============================================================
// === LOGIN ===
// ============================================================
app.post('/api/login', loginLimiter, (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ success: false, error: 'Email y contraseña requeridos' });
    }

    db.query('SELECT * FROM usuarios WHERE email = ?', [email], async (err, results) => {
        if (err) return res.status(500).json({ success: false, error: 'Error del servidor' });

        if (results.length === 0) {
            registrarAuditoria('usuarios', 0, 'crear', 'Sistema', null, {
                evento: 'LOGIN_FALLIDO',
                email,
                razon: 'Usuario no existe'
            });
            return res.status(401).json({ success: false, error: 'Correo o contraseña incorrectos' });
        }

        const u = results[0];
        const hashAlmacenado = u.password_hash || u.password;

        let passwordOk = false;
        try {
            passwordOk = await bcrypt.compare(password, hashAlmacenado);
        } catch (e) {
            passwordOk = false;
        }

        if (!passwordOk) {
            registrarAuditoria('usuarios', u.id, 'crear', u.nombre, null, {
                evento: 'LOGIN_FALLIDO',
                email,
                razon: 'Contraseña incorrecta'
            });
            return res.status(401).json({ success: false, error: 'Correo o contraseña incorrectos' });
        }

        const token = jwt.sign(
            {
                id: u.id,
                email: u.email,
                rol: u.rol || 'vendedor',
                nombre: u.nombre,
                token_version: u.token_version ?? 1
            },
            JWT_SECRET,
            { expiresIn: JWT_EXPIRES }
        );

        registrarAuditoria('usuarios', u.id, 'crear', u.nombre, null, { evento: 'LOGIN_OK', email });

        res.json({
            success: true,
            token,
            id: u.id,
            usuario: u.nombre,
            email: u.email,
            rol: u.rol || 'vendedor'
        });
    });
});

// === GOOGLE LOGIN ===
app.post('/api/auth/google', async (req, res) => {
    const { credential } = req.body;
    try {
        const ticket = await client.verifyIdToken({
            idToken: credential,
            audience: '62107681583-ebfckf4iuq0ocbgont2mg4votqp0k97i.apps.googleusercontent.com'
        });
        const { email, name: nombre } = ticket.getPayload();

        db.query('SELECT * FROM usuarios WHERE email = ?', [email], (err, results) => {
            if (err) return res.status(500).json({ success: false, error: 'Error en la BD' });

            const finalizar = (u) => {
                const token = jwt.sign(
                    {
                        id: u.id,
                        email: u.email,
                        rol: u.rol || 'vendedor',
                        nombre: u.nombre,
                        token_version: u.token_version ?? 1
                    },
                    JWT_SECRET,
                    { expiresIn: JWT_EXPIRES }
                );
                res.json({
                    success: true,
                    token,
                    id: u.id,
                    usuario: u.nombre,
                    email: u.email,
                    rol: u.rol || 'vendedor'
                });
            };

            if (results.length > 0) {
                registrarAuditoria('usuarios', results[0].id, 'crear', nombre, null, { evento: 'LOGIN_GOOGLE', email });
                return finalizar(results[0]);
            }

            return res.status(401).json({
                success: false,
                error: 'Tu correo no está autorizado. Pide al administrador que registre tu cuenta.'
            });
        });
    } catch (error) {
        console.error('Error token Google:', error);
        res.status(401).json({ success: false, error: 'Token de Google inválido' });
    }
});

// === REGISTER PÚBLICO DESHABILITADO ===
app.post('/api/register', registerLimiter, (req, res) => {
    return res.status(403).json({
        success: false,
        error: 'El registro público está deshabilitado. Solicita tu cuenta al administrador.'
    });
});

// === SUBIR IMÁGENES ===
app.post('/api/upload', verificarToken, upload.single('imagen'), (req, res) => {
    if (!req.file) return res.status(400).json({ error: 'No se recibió archivo' });
    res.json({ success: true, url: `/uploads/${req.file.filename}`, filename: req.file.filename });
});

// ============================================================
// === COTIZACIONES ===
// ============================================================
app.post('/api/guardar_cotizacion', async (req, res) => {
    const { nombre_cliente, telefono, email_cliente, tipo_servicio, falla_detectada, ubicacion, urgencia, mensaje } = req.body;
    const query = `INSERT INTO cotizaciones (nombre_cliente, telefono, email_cliente, tipo_servicio, falla_detectada, ubicacion, urgencia, mensaje_adicional) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`;
    db.query(query, [nombre_cliente, telefono, email_cliente, tipo_servicio, falla_detectada, ubicacion, urgencia, mensaje], async (err, result) => {
        if (err) { console.error(err); return res.status(500).json({ status: 'error' }); }
        const idCotizacion = result.insertId;
        registrarAuditoria('cotizaciones', idCotizacion, 'crear', nombre_cliente || 'Cliente Web', null, { tipo_servicio, urgencia, ubicacion });

        // ============================================================
        // === ENVÍO DE NOTIFICACIÓN POR WHATSAPP (CON DIAGNÓSTICO) ===
        // ============================================================
        try {
            const tokenMeta = process.env.WHATSAPP_TOKEN;
            const phoneNumberId = process.env.WHATSAPP_PHONE_ID;
            const destino = process.env.OPERATIVE_TEAM_PHONE;

            console.log('\n🔍 [WhatsApp] Intentando enviar notificación...');
            console.log('   Token:', tokenMeta ? '✅ Configurado' : '❌ NO está configurado');
            console.log('   Phone ID:', phoneNumberId || '❌ NO está configurado');
            console.log('   Destino (env):', destino || '❌ NO está configurado');

            if (tokenMeta && phoneNumberId && destino) {
                const telefonoDestino = destino.startsWith('52') ? destino : '521' + destino;
                console.log('   Teléfono final a usar:', telefonoDestino);

                const url = `https://graph.facebook.com/v25.0/${phoneNumberId}/messages`;
                const respuestaMeta = await fetch(url, {
                    method: 'POST',
                    headers: {
                        'Authorization': `Bearer ${tokenMeta}`,
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        messaging_product: 'whatsapp',
                        to: telefonoDestino,
                        type: 'template',
                        template: {
                            name: 'resumen_cotizacion',
                            language: { code: 'es' },
                            components: [{
                                type: 'body',
                                parameters: [
                                    { type: 'text', text: String(idCotizacion) },
                                    { type: 'text', text: String(nombre_cliente || 'N/A') },
                                    { type: 'text', text: String(telefono || 'N/A') },
                                    { type: 'text', text: String(tipo_servicio || 'N/A') },
                                    { type: 'text', text: String(urgencia || 'Normal') },
                                    { type: 'text', text: String(ubicacion || 'No especificada') },
                                    { type: 'text', text: String(mensaje || 'Sin observaciones') }
                                ]
                            }]
                        }
                    })
                });

                const datosRespuesta = await respuestaMeta.json();

                if (!respuestaMeta.ok) {
                    console.error('❌ [WhatsApp] Meta RECHAZÓ el mensaje:');
                    console.error('   Código HTTP:', respuestaMeta.status);
                    console.error('   Detalle:', JSON.stringify(datosRespuesta, null, 2));
                } else {
                    console.log('✅ [WhatsApp] Mensaje enviado correctamente a Meta');
                    console.log('   ID del mensaje:', datosRespuesta.messages?.[0]?.id);
                    console.log('   Contacto WA:', datosRespuesta.contacts?.[0]?.wa_id);
                }
            } else {
                console.warn('⚠️ [WhatsApp] Faltan variables en el entorno, no se envió el mensaje');
            }
            console.log('');
        } catch (errorWhatsApp) {
            console.error('❌ [WhatsApp] Error de red:', errorWhatsApp.message);
            console.error('');
        }

        res.json({ status: 'success', id_cotizacion: idCotizacion });
    });
});

app.get('/api/rastrear_cotizacion', (req, res) => {
    const { folio, email } = req.query;

    if (!folio || !email) {
        return res.status(400).json({ error: 'Folio y correo son requeridos' });
    }

    const query = 'SELECT * FROM cotizaciones WHERE id = ? AND email_cliente = ? LIMIT 1';

    db.query(query, [folio, email], (err, results) => {
        if (err) {
            console.error('Error al buscar cotización:', err);
            return res.status(500).json({ error: 'Error del servidor' });
        }
        if (results.length === 0) {
            return res.status(404).json({ error: 'No se encontró la cotización con esos datos' });
        }
        res.json(results[0]);
    });
});

app.get('/api/cotizaciones', verificarToken, (req, res) => {
    db.query('SELECT * FROM cotizaciones ORDER BY id DESC', (err, results) => {
        if (err) return res.status(500).json(err);
        res.json(results);
    });
});

app.put('/api/cotizaciones/:id', verificarToken, (req, res) => {
    const { estatus } = req.body;
    const usuarioReal = req.usuario.nombre;
    const idUsuarioReal = req.usuario.id;

    db.query('SELECT * FROM cotizaciones WHERE id = ?', [req.params.id], (err, results) => {
        if (err) return res.status(500).json(err);
        if (results.length === 0) return res.status(404).json({ error: 'No encontrada' });
        const anterior = results[0];
        const diff = obtenerDiferencias({ estatus: anterior.estatus || anterior.estado }, { estatus });

        db.query('UPDATE cotizaciones SET estatus = ?, id_usuario = ? WHERE id = ?', [estatus, idUsuarioReal, req.params.id], (err2) => {
            if (err2) return res.status(500).json(err2);
            registrarAuditoria('cotizaciones', req.params.id, 'actualizar', usuarioReal, diff.anteriores, diff.nuevos);
            res.json({ success: true });
        });
    });
});

// ============================================================
// === SERVICIOS ===
// ============================================================
app.get('/api/servicios', (req, res) => {
    db.query('SELECT * FROM servicios ORDER BY id_servicio DESC', (err, results) => {
        if (err) return res.status(500).json(err);
        res.json(results);
    });
});

app.get('/api/servicios/:id', (req, res) => {
    db.query('SELECT * FROM servicios WHERE id_servicio = ?', [req.params.id], (err, results) => {
        if (err) return res.status(500).json(err);
        if (results.length === 0) return res.status(404).json({ error: 'Servicio no encontrado' });
        res.json(results[0]);
    });
});

app.post('/api/servicios', verificarToken, adminOVendedor, (req, res) => {
    const { nombre_servicio, precio_base, imagen_url, descripcion, detalle, estado, categoria_id } = req.body;
    if (!nombre_servicio || nombre_servicio.trim() === '') {
        return res.status(400).json({ error: 'El nombre del servicio es obligatorio.' });
    }
    if (isNaN(precio_base) || precio_base < 0) {
        return res.status(400).json({ error: 'El precio base no puede ser negativo.' });
    }
    db.query(
        'INSERT INTO servicios (nombre_servicio, precio_base, imagen_url, descripcion, detalle, estado, categoria_id) VALUES (?, ?, ?, ?, ?, ?, ?)',
        [nombre_servicio, precio_base, imagen_url, descripcion, detalle || null, estado, categoria_id || 1],
        (err, result) => {
            if (err) return res.status(500).json(err);
            registrarAuditoria('servicios', result.insertId, 'crear', req.usuario.nombre, null, { nombre_servicio, precio_base });
            res.json({ id_servicio: result.insertId });
        }
    );
});

app.put('/api/servicios/:id', verificarToken, adminOVendedor, (req, res) => {
    const { nombre_servicio, precio_base, imagen_url, descripcion, detalle, estado, categoria_id } = req.body;
    if (!nombre_servicio || nombre_servicio.trim() === '') {
        return res.status(400).json({ error: 'El nombre del servicio es obligatorio.' });
    }
    if (isNaN(precio_base) || precio_base < 0) {
        return res.status(400).json({ error: 'El precio base no puede ser negativo.' });
    }
    db.query('SELECT * FROM servicios WHERE id_servicio = ?', [req.params.id], (err, results) => {
        if (err) return res.status(500).json(err);
        if (results.length === 0) return res.status(404).json({ error: 'No encontrado' });
        const anterior = results[0];
        const nuevo = { nombre_servicio, precio_base, imagen_url, descripcion, detalle, estado, categoria_id };
        const diff = obtenerDiferencias(anterior, nuevo);
        db.query(
            'UPDATE servicios SET nombre_servicio=?, precio_base=?, imagen_url=?, descripcion=?, detalle=?, estado=?, categoria_id=? WHERE id_servicio=?',
            [nombre_servicio, precio_base, imagen_url, descripcion, detalle || null, estado, categoria_id || 1, req.params.id],
            (err2) => {
                if (err2) return res.status(500).json(err2);
                registrarAuditoria('servicios', req.params.id, 'actualizar', req.usuario.nombre, diff.anteriores, diff.nuevos);
                res.json({ success: true });
            }
        );
    });
});

app.delete('/api/servicios/:id', verificarToken, adminOVendedor, (req, res) => {
    db.query('DELETE FROM servicios WHERE id_servicio = ?', [req.params.id], (err) => {
        if (err) return res.status(500).json(err);
        registrarAuditoria('servicios', req.params.id, 'eliminar', req.usuario.nombre, null, null);
        res.json({ success: true });
    });
});

// ============================================================
// === PRODUCTOS ===
// ============================================================
app.get('/api/productos', (req, res) => {
    db.query('SELECT * FROM productos ORDER BY id DESC', (err, results) => {
        if (err) return res.status(500).json(err);
        res.json(results);
    });
});

app.post('/api/productos', verificarToken, adminOVendedor, (req, res) => {
    const { nombre_producto, descripcion, precio, stock, imagen } = req.body;
    if (!nombre_producto || nombre_producto.trim() === '') {
        return res.status(400).json({ error: 'El nombre del producto es obligatorio.' });
    }
    if (isNaN(precio) || precio < 0) {
        return res.status(400).json({ error: 'El precio no puede ser negativo ni vacío.' });
    }
    if (isNaN(stock) || stock < 0) {
        return res.status(400).json({ error: 'El stock no puede ser negativo.' });
    }
    db.query(
        'INSERT INTO productos (nombre_producto, descripcion, precio, stock, imagen) VALUES (?, ?, ?, ?, ?)',
        [nombre_producto, descripcion, precio, stock, imagen],
        (err, result) => {
            if (err) return res.status(500).json(err);
            registrarAuditoria('productos', result.insertId, 'crear', req.usuario.nombre, null, { nombre_producto, precio, stock });
            res.json({ success: true, id: result.insertId });
        }
    );
});

app.put('/api/productos/:id', verificarToken, adminOVendedor, (req, res) => {
    const { nombre_producto, descripcion, precio, stock, imagen } = req.body;
    if (!nombre_producto || nombre_producto.trim() === '') {
        return res.status(400).json({ error: 'El nombre del producto es obligatorio.' });
    }
    if (isNaN(precio) || precio < 0) {
        return res.status(400).json({ error: 'El precio no puede ser negativo ni vacío.' });
    }
    if (isNaN(stock) || stock < 0) {
        return res.status(400).json({ error: 'El stock no puede ser negativo.' });
    }
    db.query('SELECT * FROM productos WHERE id = ?', [req.params.id], (err, results) => {
        if (err) return res.status(500).json(err);
        if (results.length === 0) return res.status(404).json({ error: 'No encontrado' });
        const anterior = results[0];
        const nuevo = { nombre_producto, descripcion, precio, stock, imagen };
        const diff = obtenerDiferencias(anterior, nuevo);
        db.query(
            'UPDATE productos SET nombre_producto=?, descripcion=?, precio=?, stock=?, imagen=? WHERE id=?',
            [nombre_producto, descripcion, precio, stock, imagen, req.params.id],
            (err2) => {
                if (err2) return res.status(500).json(err2);
                registrarAuditoria('productos', req.params.id, 'actualizar', req.usuario.nombre, diff.anteriores, diff.nuevos);
                res.json({ success: true });
            }
        );
    });
});

app.delete('/api/productos/:id', verificarToken, adminOVendedor, (req, res) => {
    db.query('DELETE FROM productos WHERE id = ?', [req.params.id], (err) => {
        if (err) return res.status(500).json(err);
        registrarAuditoria('productos', req.params.id, 'eliminar', req.usuario.nombre, null, null);
        res.json({ success: true });
    });
});

// ============================================================
// === USUARIOS ===
// ============================================================
app.get('/api/usuarios', verificarToken, (req, res) => {
    if (req.usuario.rol === 'admin') {
        return db.query(
            'SELECT id, nombre, email, rol, creado_en FROM usuarios ORDER BY id DESC',
            (err, results) => {
                if (err) return res.status(500).json(err);
                res.json(results);
            }
        );
    }

    if (req.usuario.rol === 'vendedor') {
        return db.query(
            "SELECT id, nombre, email, rol, creado_en FROM usuarios WHERE rol = 'vendedor' ORDER BY id DESC",
            (err, results) => {
                if (err) return res.status(500).json(err);
                res.json(results);
            }
        );
    }

    if (req.usuario.rol === 'tecnico') {
        return db.query(
            "SELECT id, nombre, email, rol, creado_en FROM usuarios WHERE rol = 'tecnico' ORDER BY id DESC",
            (err, results) => {
                if (err) return res.status(500).json(err);
                res.json(results);
            }
        );
    }

    db.query(
        'SELECT id, nombre, email, rol, creado_en FROM usuarios WHERE id = ?',
        [req.usuario.id],
        (err, results) => {
            if (err) return res.status(500).json(err);
            res.json(results);
        }
    );
});

app.post('/api/usuarios', verificarToken, soloAdmin, async (req, res) => {
    const { nombre, email, password, rol } = req.body;

    if (!nombre || !email || !password) {
        return res.status(400).json({ error: 'Nombre, email y contraseña requeridos' });
    }
    if (password.length < 6) {
        return res.status(400).json({ error: 'La contraseña debe tener al menos 6 caracteres' });
    }

    const rolFinal = ['admin', 'vendedor', 'tecnico'].includes(rol) ? rol : 'vendedor';

    db.query('SELECT id FROM usuarios WHERE email = ?', [email], async (err, dup) => {
        if (err) return res.status(500).json(err);
        if (dup.length > 0) return res.status(400).json({ error: 'Email ya registrado' });

        const hash = await bcrypt.hash(password, SALT_ROUNDS);
        db.query(
            'INSERT INTO usuarios (nombre, email, password, rol) VALUES (?, ?, ?, ?)',
            [nombre, email, hash, rolFinal],
            (err2, result) => {
                if (err2) return res.status(500).json(err2);
                registrarAuditoria('usuarios', result.insertId, 'crear', req.usuario.nombre, null, { nombre, email, rol: rolFinal });
                res.json({ id: result.insertId });
            }
        );
    });
});

app.put('/api/usuarios/:id', verificarToken, (req, res) => {
    const { id } = req.params;
    const { nombre, email, rol, password } = req.body;
    const soyAdmin = req.usuario.rol === 'admin';
    const esMiPerfil = String(id) === String(req.usuario.id);

    if (!nombre || !email) return res.status(400).json({ error: 'Nombre y email requeridos' });
    if (!soyAdmin && !esMiPerfil) return res.status(403).json({ error: 'Sin permiso' });
    if (!soyAdmin && rol !== undefined) return res.status(403).json({ error: 'Solo admin puede cambiar rol' });
    if (esMiPerfil && rol !== undefined) return res.status(403).json({ error: 'No puedes cambiar tu propio rol' });

    db.query('SELECT * FROM usuarios WHERE id = ?', [id], (err, results) => {
        if (err) return res.status(500).json(err);
        if (results.length === 0) return res.status(404).json({ error: 'No encontrado' });
        const anterior = results[0];

        db.query('SELECT id FROM usuarios WHERE email = ? AND id != ?', [email, id], async (err2, dup) => {
            if (err2) return res.status(500).json(err2);
            if (dup.length > 0) return res.status(400).json({ error: 'Email ya en uso' });

            const rolFinal = soyAdmin && !esMiPerfil ? (rol || anterior.rol) : anterior.rol;
            const cambioRol = rolFinal !== anterior.rol;
            const cambioPass = Boolean(password && password.trim() !== '');
            const incrementarVersion = cambioRol || cambioPass;

            let query, params;
            if (cambioPass) {
                if (password.length < 6) return res.status(400).json({ error: 'Contraseña muy corta' });
                const hash = await bcrypt.hash(password, SALT_ROUNDS);
                query = incrementarVersion
                    ? 'UPDATE usuarios SET nombre=?, email=?, rol=?, password=?, token_version = token_version + 1 WHERE id=?'
                    : 'UPDATE usuarios SET nombre=?, email=?, rol=?, password=? WHERE id=?';
                params = [nombre, email, rolFinal, hash, id];
            } else {
                query = incrementarVersion
                    ? 'UPDATE usuarios SET nombre=?, email=?, rol=?, token_version = token_version + 1 WHERE id=?'
                    : 'UPDATE usuarios SET nombre=?, email=?, rol=? WHERE id=?';
                params = [nombre, email, rolFinal, id];
            }

            const diff = obtenerDiferencias(
                { nombre: anterior.nombre, email: anterior.email, rol: anterior.rol },
                { nombre, email, rol: rolFinal }
            );

            db.query(query, params, (err3) => {
                if (err3) return res.status(500).json(err3);
                registrarAuditoria('usuarios', id, 'actualizar', req.usuario.nombre, diff.anteriores, diff.nuevos);
                res.json({ success: true });
            });
        });
    });
});

app.delete('/api/usuarios/:id', verificarToken, soloAdmin, (req, res) => {
    if (String(req.params.id) === String(req.usuario.id)) {
        return res.status(400).json({ error: 'No puedes eliminar tu propia cuenta.' });
    }
    db.query('DELETE FROM usuarios WHERE id = ?', [req.params.id], (err) => {
        if (err) return res.status(500).json(err);
        registrarAuditoria('usuarios', req.params.id, 'eliminar', req.usuario.nombre, null, null);
        res.json({ success: true });
    });
});

// ============================================================
// === AUDITORÍA Y CONFIGURACIÓN ===
// ============================================================
app.get('/api/auditoria', verificarToken, soloAdmin, (req, res) => {
    db.query('SELECT * FROM auditoria ORDER BY id DESC LIMIT 200', (err, results) => {
        if (err) return res.status(500).json(err);
        res.json(results);
    });
});

app.get('/api/configuracion', (req, res) => {
    db.query('SELECT * FROM configuracion LIMIT 1', (err, results) => {
        if (err) return res.status(500).json(err);
        res.json(results[0] || {});
    });
});

app.post('/api/configuracion', verificarToken, soloAdmin, (req, res) => {
    const datos = req.body;
    db.query('SELECT id FROM configuracion LIMIT 1', (err, results) => {
        if (err) return res.status(500).json(err);
        if (results.length === 0) {
            db.query('INSERT INTO configuracion SET ?', [datos], (err2) => {
                if (err2) return res.status(500).json(err2);
                registrarAuditoria('configuracion', 1, 'crear', req.usuario.nombre, null, datos);
                res.json({ success: true });
            });
        } else {
            const idConfig = results[0].id;
            db.query('UPDATE configuracion SET ? WHERE id = ?', [datos, idConfig], (err2) => {
                if (err2) return res.status(500).json(err2);
                registrarAuditoria('configuracion', idConfig, 'actualizar', req.usuario.nombre, null, datos);
                res.json({ success: true });
            });
        }
    });
});

// ============================================================
// === MANEJO DE ERRORES Y ARRANQUE ===
// ============================================================
app.use((err, req, res, next) => {
    console.error('❌ Error:', err.message);
    res.status(500).json({ error: 'Error interno del servidor' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`🚀 Servidor seguro en puerto ${PORT}`);
    console.log('🔒 JWT + bcrypt + rate limiting activados');
});