// ============================
// 📦 IMPORTACIONES Y CONFIGURACIÓN INICIAL
// ============================
const express = require('express');
const path = require('path');
const session = require('express-session');
const admin = require('firebase-admin');
const bcrypt = require('bcrypt');
const cookieParser = require('cookie-parser');
const SALT_ROUNDS = 10;

// Crear la app Express **antes** de usar app.use
const app = express();

// Usar cookieParser con la clave secreta
app.use(cookieParser('MiClaveSuperSecreta123!@#'));

// Inicializa Firebase Admin
const serviceAccount = require('./data/serviceAccountKey.json');

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

const db = admin.firestore();

// ============================
// 🔐 CONFIGURAR CLAVE SEGURA PARA ADMINISTRADORES
// ============================
async function configurarClaveSegura() {
  const claveSegura = '1234'; // Cambia por la contraseña que desees
  try {
    const hashedPassword = await bcrypt.hash(claveSegura, SALT_ROUNDS);

    const administradoresRef = db.collection('administradores');
    const snapshot = await administradoresRef.get();

    if (snapshot.empty) {
      return;
    }

    snapshot.forEach(async (doc) => {
      await administradoresRef.doc(doc.id).update({
        password: hashedPassword,
        updated_at: admin.firestore.FieldValue.serverTimestamp(),
      });
    });

  } catch (err) {
    // Aquí podrías manejar el error sin mostrar nada en consola
  }
}

// Llama a la función solo una vez para configurar la contraseña
// Retira este llamado después de haber ejecutado la configuración
configurarClaveSegura();

// ============================
// 📋 FUNCIONES DE USUARIO (con Firestore)
// ============================

// Verificar si el correo ya existe
async function verificarCorreo(correo) {
  const usuariosRef = db.collection('usuarios');
  const snapshot = await usuariosRef.where('correo', '==', correo).get();
  return !snapshot.empty; // true si hay usuarios con ese correo
}

// Registrar usuario
async function registrarUsuario({
  nombre,
  apellido_paterno,
  apellido_materno,
  calle,
  colonia,
  ciudad,
  codigo_postal,
  telefono,
  correo,
  password,
}) {
  const usuariosRef = db.collection('usuarios');
  const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);

  const nuevoDoc = usuariosRef.doc(); // crea documento con ID generado automáticamente
  const id = nuevoDoc.id; // obtener el ID generado

  await nuevoDoc.set({
    id_usuario: id, // guardamos el ID dentro del mismo documento (opcional)
    nombre,
    apellido_paterno,
    apellido_materno,
    direccion: {
      calle,
      colonia,
      ciudad,
      codigo_postal,
    },
    telefono,
    correo,
    password: hashedPassword,
    created_at: admin.firestore.FieldValue.serverTimestamp(),
    updated_at: admin.firestore.FieldValue.serverTimestamp(),
  });
}

// Login usuario
async function loginUsuario(correo, password) {
  const usuariosRef = db.collection('usuarios');
  const snapshot = await usuariosRef.where('correo', '==', correo).limit(1).get();

  if (snapshot.empty) return null;

  const usuarioDoc = snapshot.docs[0];
  const usuarioData = usuarioDoc.data();

  // Comparar contraseña con hash almacenado
  const isPasswordValid = await bcrypt.compare(password, usuarioData.password);
  if (!isPasswordValid) return null;

  // No incluir contraseña ni datos sensibles al retornar
  const { password: _, ...usuarioSinPassword } = usuarioData;
  return { id: usuarioDoc.id, ...usuarioSinPassword };
}

// ============================
// 🚀 CONFIGURACIÓN DEL SERVIDOR
// ============================


app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.use(
  session({
secret: 'MiClaveSuperSecreta123!@#',
    resave: false,
    saveUninitialized: false,
    cookie: {
      maxAge: 1000 * 60 * 60 * 24, // Duración: 1 día en milisegundos
      httpOnly: true,               // Cookie no accesible desde JS (más segura)
      secure: false,                // Cambiar a true si usas HTTPS
      sameSite: 'lax',              // Previene CSRF en la mayoría de casos
    },
  })
);

// ============================
// 🔒 MIDDLEWARE PARA PROTEGER RUTAS
// ============================

// Middleware genérico para validar que el usuario esté logueado
function requireLogin(req, res, next) {
  if (!req.session.user)
    return res.redirect('/login?error=Debes+iniciar+sesión+primero');
  next();
}

// Middleware para validar rol (user o admin)
function requireRole(role) {
  return (req, res, next) => {
    if (!req.session.user) {
      return res.redirect('/login?error=Debes+iniciar+sesión+primero');
    }
    if (req.session.user.role !== role) {
      return res.status(403).send('Acceso denegado.');
    }
    next();
  };
}

// ============================
// 🔁 RUTAS PÚBLICAS Y DE AUTENTICACIÓN
// ============================

app.get('/', (req, res) => {
  res.redirect('/bienvenido');
});

app.get('/bienvenido', (req, res) => {
  res.render('Bienvenido', { title: 'Bienvenido', user: req.session.user || null });
});

app.get('/login', (req, res) => {
  // No enviamos datos de usuario ni información previa
  res.render('Login', { title: 'Login', error: null, success: req.query.success || null });
});

app.post('/login', async (req, res) => {
  const { identificador: correo, password } = req.body;

  if (!correo || !password) {
    return res.render('Login', {
      title: 'Login',
      error: 'Por favor, completa todos los campos.',
      success: null,
    });
  }

  try {
    // Buscar en la colección de usuarios
    const usuariosSnap = await db.collection('usuarios').where('correo', '==', correo).limit(1).get();
    if (!usuariosSnap.empty) {
      const usuarioDoc = usuariosSnap.docs[0];
      const usuarioData = usuarioDoc.data();

      // Comparar contraseña
      const isPasswordValid = await bcrypt.compare(password, usuarioData.password);
      if (isPasswordValid) {
        req.session.user = {
          id: usuarioDoc.id,
          ...usuarioData,
          role: 'user',
        };
        return res.redirect('/menu');
      }
    }

    // Buscar en la colección de administradores
    const adminSnap = await db.collection('administradores').where('correo', '==', correo).limit(1).get();
    if (!adminSnap.empty) {
      const adminDoc = adminSnap.docs[0];
      const adminData = adminDoc.data();

      // Comparar contraseña
      const isPasswordValid = await bcrypt.compare(password, adminData.password);
      if (isPasswordValid) {
        req.session.user = {
          id: adminDoc.id,
          ...adminData,
          role: 'admin',
        };
        return res.redirect('/admin');
      }
    }

    // Si no encuentra en ninguna colección
    res.render('Login', {
      title: 'Login',
      error: 'Correo o contraseña incorrectos.',
      success: null,
    });
  } catch (error) {
    res.render('Login', {
      title: 'Login',
      error: 'Error en el servidor. Inténtalo más tarde.',
      success: null,
    });
  }
});


app.get('/registro', (req, res) => {
  // Aquí tampoco enviamos datos previos ni usuario
  res.render('crearCuenta', { title: 'Registro', error: null });
});

app.post('/registro', async (req, res) => {
  const {
    nombre,
    apellido_paterno,
    apellido_materno,
    calle,
    colonia,
    ciudad,
    codigo_postal,
    telefono,
    correo,
    password,
  } = req.body;

  if (
    !nombre ||
    !apellido_paterno ||
    !apellido_materno ||
    !calle ||
    !colonia ||
    !ciudad ||
    !codigo_postal ||
    !telefono ||
    !correo ||
    !password
  ) {
    return res.render('crearCuenta', {
      title: 'Registro',
      error: 'Por favor, completa todos los campos.',
    });
  }

  try {
    if (await verificarCorreo(correo)) {
      return res.render('crearCuenta', {
        title: 'Registro',
        error: 'Este correo ya está registrado.',
      });
    }

    await registrarUsuario({
      nombre,
      apellido_paterno,
      apellido_materno,
      calle,
      colonia,
      ciudad,
      codigo_postal,
      telefono,
      correo,
      password,
    });

    req.session.user = await loginUsuario(correo, password);
    res.redirect('/menu');
  } catch (err) {
    console.error('Error registro:', err);
    res.render('crearCuenta', {
      title: 'Registro',
      error: 'Error en el servidor. Inténtalo más tarde.',
    });
  }
});

app.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/login'));
});

// ============================
// 🔒 RUTAS PROTEGIDAS CON SESIÓN Y ROL
// ============================

// Ruta para usuarios normales
app.get('/menu', requireRole('user'), (req, res) => {
  res.render('Menu', { title: 'Menú Principal', user: req.session.user });
});

// Ruta exclusiva para admins
app.get('/admin', requireRole('admin'), (req, res) => {
  res.render('Admins', { title: 'Panel de Administrador', user: req.session.user });
});

app.get('/acerca_del_albergue', requireLogin, (req, res) => {
  res.render('AcercaDelAlbergue', { title: 'Acerca del Albergue', user: req.session.user });
});

app.get('/infoAdopciones', requireLogin, (req, res) => {
  res.render('InfoAdopciones', { title: 'Información sobre Adopciones', user: req.session.user });
});

app.get('/infoDonaciones', requireLogin, (req, res) => {
  res.render('InfoDonaciones', { title: 'Información sobre Donaciones', user: req.session.user });
});

app.get('/infoReportes', requireLogin, (req, res) => {
  res.render('InfoReportes', { title: 'Información sobre Reportes', user: req.session.user });
});



// ============================
// 🐶 RUTAS RELACIONADAS CON PERROS
// ============================
app.get('/perros', requireLogin, async (req, res) => {
  try {
    const perrosSnapshot = await db.collection('perros').get();
    const perros = perrosSnapshot.docs.map((doc) => ({ id: doc.id, ...doc.data() }));
    res.render('Perros', { title: 'Nuestros Perros', user: req.session.user, perros });
  } catch (err) {
    console.error('Error al obtener perros:', err);
    res.status(500).render('Perros', {
      title: 'Nuestros Perros',
      user: req.session.user,
      perros: [],
      error: 'No se pudieron cargar los perros.',
    });
  }
});

app.get('/perros/:id', requireLogin, async (req, res) => {
  try {
    const perroDoc = await db.collection('perros').doc(req.params.id).get();
    if (!perroDoc.exists)
      return res.status(404).render('404', {
        title: 'Perro no encontrado',
        user: req.session.user,
      });
    const perro = { id: perroDoc.id, ...perroDoc.data() };
    res.render('DetallesPerros', {
      title: `Detalles de ${perro.nombre}`,
      user: req.session.user,
      perro,
    });
  } catch (err) {
    console.error('Error detalles perro:', err);
    res.status(500).render('DetallesPerros', {
      title: 'Error al cargar detalles',
      user: req.session.user,
      perro: null,
      error: 'No se pudieron cargar los detalles.',
    });
  }
});

// ========== NUEVAS RUTAS PARA FORMULARIO DE ADOPCIÓN ============

app.get('/adoptar/:id', requireLogin, async (req, res) => {
  try {
    const perroDoc = await db.collection('perros').doc(req.params.id).get();
    if (!perroDoc.exists) {
      return res.status(404).render('404', { title: 'Perro no encontrado', user: req.session.user || null });
    }
    const perro = { id: perroDoc.id, ...perroDoc.data() };
    res.render('FormularioAdopcion', { title: 'Solicitud de Adopción', user: req.session.user, perro });
  } catch (err) {
    console.error('Error cargando formulario de adopción:', err);
    res.status(500).send('Error interno del servidor');
  }
});

app.post('/adoptar/:id/enviar', requireLogin, async (req, res) => {
  try {
    const id_usuario = req.session.user.id;
    const nombreCompleto = [
      req.session.user.nombre,
      req.session.user.apellido_paterno,
      req.session.user.apellido_materno,
    ].filter(Boolean).join(' ');

    const id_perro = req.params.id;

    const {
      vivienda,
      tiempo,
      mascotas_actuales,
      experiencia,
      motivo_adopcion,
      conocimiento_cuidado,
      responsable_financiero,
      acuerdo_vivienda,
      actividad_fisica,
      tiempo_compromiso,
    } = req.body;

    if (
      !vivienda || !tiempo || !mascotas_actuales || !experiencia || !motivo_adopcion ||
      !conocimiento_cuidado || !responsable_financiero || !acuerdo_vivienda ||
      !actividad_fisica || !tiempo_compromiso
    ) {
      return res.status(400).send('Por favor, completa todos los campos.');
    }

    await db.collection('solicitudes_adopcion').add({
      id_usuario,
      nombre_completo: nombreCompleto,
      id_perro,
      vivienda,
      tiempo,
      mascotas_actuales,
      experiencia,
      motivo_adopcion,
      conocimiento_cuidado,
      responsable_financiero,
      acuerdo_vivienda,
      actividad_fisica,
      tiempo_compromiso,
      fecha_solicitud: admin.firestore.FieldValue.serverTimestamp(),
      estado: 'pendiente',
      updated_at: admin.firestore.FieldValue.serverTimestamp(),
    });

    res.redirect('/menu');
  } catch (err) {
    console.error('Error al guardar solicitud:', err);
    res.status(500).send('Error interno del servidor');
  }
});

// ============================
// 📝 FORMULARIO DE REPORTES (sin cambiar ruta ni lógica)
// ============================
app.get('/FormularioReportes', requireLogin, (req, res) => {
  res.render('FormularioReportes', {
    title: 'Formulario de Reportes',
    user: req.session.user,
    error: null,
    success: null,
    formData: {},
  });
});

app.post('/Form_Reporte', requireLogin, async (req, res) => {
  try {
    const id_usuario = req.session.user?.id;
    if (!id_usuario) throw new Error('Usuario no autenticado.');

    const { tipodemaltrato, fecha, pruebas, pruebasOtro } = req.body;

    if (!tipodemaltrato) throw new Error('Seleccione un motivo de maltrato.');
    if (!fecha) throw new Error('Ingrese la fecha aproximada.');

    let pruebasArray = [];
    if (pruebas) {
      if (Array.isArray(pruebas)) {
        pruebasArray = pruebas;
      } else {
        pruebasArray = [pruebas];
      }
    }

    await db.collection('reportes').add({
      id_usuario,
      tipoDeMaltrato: tipodemaltrato,
      fecha: new Date(fecha),
      pruebas: pruebasArray.join(', '),
      pruebasOtro: pruebasOtro || '',
      creado_en: admin.firestore.FieldValue.serverTimestamp(),
      updated_at: admin.firestore.FieldValue.serverTimestamp(),
    });

    res.render('FormularioReportes', {
      title: 'Formulario de Reportes',
      user: req.session.user,
      error: null,
      success: 'Reporte guardado con éxito. ¡Gracias por ayudar!',
      formData: {},
    });
  } catch (err) {
    console.error('Error al guardar reporte:', err);
    res.render('FormularioReportes', {
      title: 'Formulario de Reportes',
      user: req.session.user,
      error: err.message || 'Error al guardar el reporte.',
      success: null,
      formData: req.body,
    });
  }
});

// ============================
// 💰 FORMULARIO Y PROCESO DE DONACIONES (adaptado Firestore)
// ============================
app.get('/FormularioDonaciones', requireLogin, (req, res) => {
  res.render('FormularioDonaciones', {
    title: 'Formulario de Donaciones',
    user: req.session.user,
    error: null,
    success: null,
    formData: {},
  });
});

app.post('/donaciones/guardar', requireLogin, async (req, res) => {
  try {
    const id_usuario = req.session.user?.id;
    if (!id_usuario) throw new Error('Usuario no autenticado.');

    const { monto, metodoPago, material, materialOtro } = req.body;

    if ((!monto || Number(monto) <= 0) && (!material || material.length === 0)) {
      throw new Error('Debe donar algo: monto o material.');
    }

    const donacionData = {
      id_usuario,
      creado_en: admin.firestore.FieldValue.serverTimestamp(),
      updated_at: admin.firestore.FieldValue.serverTimestamp(),
    };

    if (monto && Number(monto) > 0) {
      donacionData.monto = Number(monto);
      donacionData.metodoPago = metodoPago || null;
    }

    if (material && material.length > 0) {
      const materialesArray = Array.isArray(material) ? material : [material];
      donacionData.material = materialesArray.join(', ');
      donacionData.materialOtro = materialOtro || '';
    }

    await db.collection('donaciones').add(donacionData);

    res.render('FormularioDonaciones', {
      title: 'Formulario de Donaciones',
      user: req.session.user,
      error: null,
      success: 'Donación guardada con éxito. ¡Gracias!',
      formData: {},
    });
  } catch (err) {
    console.error('Error al guardar donación:', err);
    res.render('FormularioDonaciones', {
      title: 'Formulario de Donaciones',
      user: req.session.user,
      error: err.message || 'Error procesando la donación.',
      success: null,
      formData: req.body,
    });
  }
});

// ============================
// 🔀 RUTAS DE SINCRONIZACIÓN / POLLING
// ============================
app.get('/sync/perros', requireLogin, async (req, res) => {
  try {
    const since = req.query.since ? new Date(req.query.since) : new Date(0);

    const perrosRef = db.collection('perros');
    const snapshot = await perrosRef
      .where('updated_at', '>', since)
      .get();

    const perros = snapshot.docs.map(doc => ({
      id: doc.id,
      ...doc.data()
    }));

    res.json({ success: true, data: perros });
  } catch (err) {
    console.error('Error sincronizando perros:', err);
    res.status(500).json({ success: false, error: 'Error del servidor.' });
  }
});

app.get('/sync/usuarios', requireLogin, async (req, res) => {
  try {
    const since = req.query.since ? new Date(req.query.since) : new Date(0);

    const usuariosRef = db.collection('usuarios');
    const snapshot = await usuariosRef
      .where('updated_at', '>', since)
      .get();

    const usuarios = snapshot.docs.map(doc => ({
      id: doc.id,
      ...doc.data()
    }));

    res.json({ success: true, data: usuarios });
  } catch (err) {
    console.error('Error sincronizando usuarios:', err);
    res.status(500).json({ success: false, error: 'Error del servidor.' });
  }
});

app.get('/sync/donaciones', requireLogin, async (req, res) => {
  try {
    const since = req.query.since ? new Date(req.query.since) : new Date(0);

    const donacionesRef = db.collection('donaciones');
    const snapshot = await donacionesRef
      .where('updated_at', '>', since)
      .get();

    const donaciones = snapshot.docs.map(doc => ({
      id: doc.id,
      ...doc.data()
    }));

    res.json({ success: true, data: donaciones });
  } catch (err) {
    console.error('Error sincronizando donaciones:', err);
    res.status(500).json({ success: false, error: 'Error del servidor.' });
  }
});

app.get('/sync/reportes', requireLogin, async (req, res) => {
  try {
    const since = req.query.since ? new Date(req.query.since) : new Date(0);

    const reportesRef = db.collection('reportes');
    const snapshot = await reportesRef
      .where('updated_at', '>', since)
      .get();

    const reportes = snapshot.docs.map(doc => ({
      id: doc.id,
      ...doc.data()
    }));

    res.json({ success: true, data: reportes });
  } catch (err) {
    console.error('Error sincronizando reportes:', err);
    res.status(500).json({ success: false, error: 'Error del servidor.' });
  }
});
app.get('/usuarios', requireRole('admin'), async (req, res) => {
  try {
    const snapshot = await db.collection('usuarios').orderBy('nombre').get();
    const usuarios = snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));
    res.render('GestionUsuarios', { title: 'Gestión de Usuarios', user: req.session.user, usuarios });
  } catch (err) {
    console.error('Error al obtener usuarios:', err);
    res.status(500).send('Error al obtener usuarios');
  }
});
app.post('/usuarios/:id/editar', requireRole('admin'), async (req, res) => {
  const {
    nombre, apellido_paterno, apellido_materno,
    calle, colonia, ciudad, codigo_postal,
    telefono, correo
  } = req.body;

  if (!nombre || !apellido_paterno || !apellido_materno || !calle || !colonia || !ciudad || !codigo_postal || !telefono || !correo) {
    return res.render('EditarUsuario', {
      title: 'Editar Usuario',
      user: req.session.user,
      usuario: { id: req.params.id, ...req.body },
      error: 'Completa todos los campos.',
    });
  }

  try {
    await db.collection('usuarios').doc(req.params.id).update({
      nombre,
      apellido_paterno,
      apellido_materno,
      direccion: { calle, colonia, ciudad, codigo_postal },
      telefono,
      correo,
      updated_at: admin.firestore.FieldValue.serverTimestamp(),
    });
    res.redirect('/usuarios');
  } catch (err) {
    console.error('Error al actualizar usuario:', err);
    res.status(500).send('Error al actualizar usuario');
  }
});
app.post('/usuarios/:id/estado', requireRole('admin'), async (req, res) => {
  try {
    const nuevoEstado = req.body.activo === 'true';
    await db.collection('usuarios').doc(req.params.id).update({
      activo: nuevoEstado,
      updated_at: admin.firestore.FieldValue.serverTimestamp(),
    });
    res.redirect('/usuarios');
  } catch (err) {
    console.error('Error al cambiar estado:', err);
    res.status(500).send('Error al actualizar estado');
  }
});





// ============================
// 🛑 RUTA 404 PARA TODO LO DEMÁS
// ============================
app.use((req, res) => {
  res.status(404).render('404', { title: 'Página no encontrada', user: req.session.user || null });
});

// ============================
// 🔥 INICIAR SERVIDOR
// ============================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Servidor iniciado en http://localhost:${PORT}`);
});