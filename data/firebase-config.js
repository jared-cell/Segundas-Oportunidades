const { initializeApp, cert } = require('firebase-admin/app');
const { getFirestore } = require('firebase-admin/firestore');
const serviceAccount = require('./data/serviceAccountKey.json'); // Asegúrate del path correcto

// Inicializar Firebase Admin con la clave privada
initializeApp({
  credential: cert(serviceAccount),
});

const db = getFirestore();

module.exports = { db };
