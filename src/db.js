const { createClient } = require('@libsql/client');
const crypto = require('crypto');

const DEPARTMENTS = ['HRGA', 'MINING', 'PLAN', 'HSE', 'LOGISTIK', 'VENDOR', 'VISITOR'];

// Koneksi ke Turso menggunakan Environment Variables
const db = createClient({
  url: process.env.TURSO_DATABASE_URL,
  authToken: process.env.TURSO_AUTH_TOKEN,
});

// Fungsi inisialisasi database (dijalankan sekali saat aplikasi start)
async function initDb() {
  await db.execute(`
    CREATE TABLE IF NOT EXISTS employees (
      id INTEGER PRIMARY KEY, nik TEXT UNIQUE NOT NULL, name TEXT NOT NULL, phone TEXT, active INTEGER NOT NULL DEFAULT 1
    );
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL,
      role TEXT NOT NULL CHECK(role IN ('EMPLOYEE','SUPERVISOR','HR','ADMIN')),
      employee_id INTEGER NOT NULL REFERENCES employees(id)
    );
    CREATE TABLE IF NOT EXISTS dept_supervisors (
      department TEXT NOT NULL, user_id INTEGER NOT NULL REFERENCES users(id), PRIMARY KEY (department, user_id)
    );
    CREATE TABLE IF NOT EXISTS request_approvals (
      id INTEGER PRIMARY KEY, request_id INTEGER NOT NULL, level TEXT NOT NULL, approver TEXT NOT NULL, action TEXT NOT NULL, note TEXT,
      created_at TEXT DEFAULT (datetime('now','localtime'))
    );
    CREATE TABLE IF NOT EXISTS approval_rules (
      id INTEGER PRIMARY KEY, leave_type TEXT UNIQUE NOT NULL, label TEXT NOT NULL,
      auto_approve INTEGER NOT NULL DEFAULT 0, max_days INTEGER, active INTEGER NOT NULL DEFAULT 1
    );
    CREATE TABLE IF NOT EXISTS notifications (
      id INTEGER PRIMARY KEY, employee_id INTEGER NOT NULL DEFAULT 0, phone TEXT, message TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'QUEUED', attempts INTEGER NOT NULL DEFAULT 0, created_at TEXT DEFAULT (datetime('now','localtime'))
    );
    CREATE INDEX IF NOT EXISTS idx_notif_status ON notifications(status);
    CREATE TABLE IF NOT EXISTS audit_logs (
      id INTEGER PRIMARY KEY, actor TEXT NOT NULL, action TEXT NOT NULL, entity TEXT, entity_id INTEGER, detail TEXT,
      created_at TEXT DEFAULT (datetime('now','localtime'))
    );
    CREATE TABLE IF NOT EXISTS counters (name TEXT PRIMARY KEY, value INTEGER NOT NULL);
    CREATE TABLE IF NOT EXISTS leave_requests (
      id INTEGER PRIMARY KEY, request_no TEXT UNIQUE, employee_id INTEGER,
      applicant_name TEXT NOT NULL, applicant_nik TEXT NOT NULL, applicant_position TEXT NOT NULL, department TEXT NOT NULL, phone TEXT,
      leave_type TEXT NOT NULL, start_date TEXT NOT NULL, end_date TEXT NOT NULL, reason TEXT NOT NULL, status TEXT NOT NULL, reject_reason TEXT,
      version INTEGER NOT NULL DEFAULT 1, owner_hash TEXT,
      created_at TEXT DEFAULT (datetime('now','localtime')), updated_at TEXT DEFAULT (datetime('now','localtime'))
    );
    CREATE INDEX IF NOT EXISTS idx_lr_owner ON leave_requests(owner_hash);
    CREATE INDEX IF NOT EXISTS idx_lr_dept ON leave_requests(department, status);
    CREATE INDEX IF NOT EXISTS idx_lr_nik ON leave_requests(applicant_nik);
    CREATE INDEX IF NOT EXISTS idx_lr_status ON leave_requests(status);
  `);

  // Inisialisasi akun admin default jika belum ada
  const adminCheck = await db.execute("SELECT 1 FROM users WHERE role='ADMIN'");
  if (adminCheck.rows.length === 0) {
    const defaultPassword = process.env.DEFAULT_ADMIN_PASSWORD || 'password123';
    const pwHash = hash(defaultPassword);
    await db.execute({
      sql: "INSERT OR IGNORE INTO employees(nik,name,phone) VALUES ('A001','Admin Sistem','6281200000005')",
      args: []
    });
    const emp = await db.execute("SELECT id FROM employees WHERE nik='A001'");
    const eid = emp.rows[0].id;
    await db.execute({
      sql: "INSERT INTO users(username,password_hash,role,employee_id) VALUES ('admin',?, 'ADMIN',?)",
      args: [pwHash, eid]
    });
  }
}

const hash = (pw) => {
  const s = crypto.randomBytes(16).toString('hex');
  return s + ':' + crypto.scryptSync(pw, s, 32).toString('hex');
};

const verify = (pw, h) => {
  const [s, k] = h.split(':');
  return crypto.timingSafeEqual(Buffer.from(k, 'hex'), crypto.scryptSync(pw, s, 32));
};

module.exports = { db, initDb, hash, verify, DEPARTMENTS };