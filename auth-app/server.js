const express = require('express');
const fs = require('fs');
const path = require('path');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const morgan = require('morgan');

const app = express();
app.use(express.json());
app.use(cors());
app.use(morgan('dev'));
app.use(express.static(path.join(__dirname, 'public')));

// Rutas y archivos
const USERS_FILE = path.join(__dirname, 'usuarios.txt');
const PRIVATE_KEY = fs.readFileSync(path.join(__dirname, 'keys', 'private.pem'), 'utf8'); // firma
const PUBLIC_KEY  = fs.readFileSync(path.join(__dirname, 'keys', 'public.pem'), 'utf8');  // verificación

// Utilidades para leer/escribir usuarios
function readUsers() {
  if (!fs.existsSync(USERS_FILE)) return [];
  const raw = fs.readFileSync(USERS_FILE, 'utf8').trim();
  if (!raw) return [];
  return raw.split('\n').map(line => {
    const [rol, nombre, clave] = line.split(';');
    return { rol: rol?.trim(), nombre: nombre?.trim(), clave: clave?.trim() };
  });
}

function userExists(nombre) {
  return readUsers().some(u => u.nombre === nombre);
}

function appendUser({ rol, nombre, clave }) {
  const linea = `${rol};${nombre};${clave}\n`;
  fs.appendFileSync(USERS_FILE, linea, 'utf8');
}

// === Middleware preauthorizer (valida Bearer JWT) ===
function preauthorizer(rolesPermitidos = []) {
  return (req, res, next) => {
    try {
      const auth = req.headers.authorization || '';
      const [type, token] = auth.split(' ');
      if (type !== 'Bearer' || !token) {
        return res.status(401).json({ error: 'Falta token Bearer' });
      }

      // Verificar firma y expiración con la LLAVE PÚBLICA
      const payload = jwt.verify(token, PUBLIC_KEY, { algorithms: ['RS256'] });

      // Si hay restricción de roles, validar
      if (rolesPermitidos.length > 0 && !rolesPermitidos.includes(payload.rol)) {
        return res.status(403).json({ error: 'No tienes permisos para este recurso' });
      }

      // Guardar payload por si se usa después
      req.user = payload;
      next();
    } catch (err) {
      // jwt.TokenExpiredError / jwt.JsonWebTokenError
      return res.status(401).json({ error: 'Token inválido o expirado' });
    }
  };
}

// === AUTH ===

// Registro: agrega usuario a usuarios.txt
// body: { rol, nombre, clave }
app.post('/register', (req, res) => {
  try {
    const { rol, nombre, clave } = req.body || {};
    if (!rol || !nombre || !clave) {
      return res.status(400).json({ error: 'rol, nombre y clave son requeridos' });
    }
    if (!['basic', 'admin'].includes(rol)) {
      return res.status(400).json({ error: 'rol debe ser basic o admin' });
    }
    if (userExists(nombre)) {
      return res.status(409).json({ error: 'El usuario ya existe' });
    }
    appendUser({ rol, nombre, clave });
    return res.json({ ok: true, message: 'Usuario registrado' });
  } catch (e) {
    return res.status(500).json({ error: 'Error registrando usuario' });
  }
});

// Login: valida contra usuarios.txt y genera JWT (2 minutos)
app.post('/login', (req, res) => {
  try {
    const { nombre, clave } = req.body || {};
    if (!nombre || !clave) {
      return res.status(400).json({ error: 'nombre y clave son requeridos' });
    }
    const users = readUsers();
    const user = users.find(u => u.nombre === nombre && u.clave === clave);
    if (!user) {
      return res.status(401).json({ error: 'Credenciales inválidas' });
    }

    // expira en 2 minutos
    const token = jwt.sign(
      { sub: user.nombre, rol: user.rol },
      PRIVATE_KEY,
      { algorithm: 'RS256', expiresIn: '2m' }
    );

    return res.json({ ok: true, token });
  } catch (e) {
    return res.status(500).json({ error: 'Error en login' });
  }
});

// === PROTEGIDOS ===

app.get('/saludo', preauthorizer(['basic', 'admin']), (req, res) => {
  res.json({ message: `Hola, ${req.user.sub}!` });
});

app.get('/despido', preauthorizer(['admin']), (req, res) => {
  res.json({ message: `Adiós, ${req.user.sub}!` });
});

// Arranque
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`API escuchando en http://localhost:${PORT}`));
