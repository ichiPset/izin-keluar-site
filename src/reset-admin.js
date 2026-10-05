// Jalankan: node src/reset-admin.js  -> akun admin dibuat/direset (username: admin, password: password123)
const { ensureAdmin } = require('./db');
ensureAdmin(true);
console.log('OK. Login dengan username: admin | password: password123');
