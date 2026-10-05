const { DatabaseSync } = require('node:sqlite'); // bawaan Node 22.13+, tanpa kompilasi
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

const DEPARTMENTS = ['HRGA', 'MINING', 'PLAN', 'HSE', 'LOGISTIK', 'VENDOR', 'VISITOR'];
fs.mkdirSync(path.join(__dirname, '../data'), { recursive: true });
const raw = new DatabaseSync(process.env.DB_FILE || path.join(__dirname, '../data/app.db'));
const db = {
  exec: (q) => raw.exec(q),
  prepare: (q) => raw.prepare(q),
  pragma: (q) => raw.exec('PRAGMA ' + q),
  transaction: (fn) => (...a) => {   // BEGIN IMMEDIATE: penulis diserialkan, aman untuk concurrency
    raw.exec('BEGIN IMMEDIATE');
    try { const r = fn(...a); raw.exec('COMMIT'); return r; } catch (e) { raw.exec('ROLLBACK'); throw e; }
  },
};
db.pragma('journal_mode = WAL');
db.pragma('busy_timeout = 5000');
db.pragma('foreign_keys = ON');

// employees = profil petugas (atasan/HR/admin). Karyawan pemohon TIDAK didaftarkan.
db.exec(`
CREATE TABLE IF NOT EXISTS employees (
  id INTEGER PRIMARY KEY, nik TEXT UNIQUE NOT NULL, name TEXT NOT NULL, phone TEXT, active INTEGER NOT NULL DEFAULT 1);
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK(role IN ('EMPLOYEE','SUPERVISOR','HR','ADMIN')),
  employee_id INTEGER NOT NULL REFERENCES employees(id));
CREATE TABLE IF NOT EXISTS dept_supervisors (   -- departemen -> atasan (diatur admin)
  department TEXT NOT NULL, user_id INTEGER NOT NULL REFERENCES users(id), PRIMARY KEY (department, user_id));
CREATE TABLE IF NOT EXISTS request_approvals (
  id INTEGER PRIMARY KEY, request_id INTEGER NOT NULL, level TEXT NOT NULL, approver TEXT NOT NULL, action TEXT NOT NULL, note TEXT,
  created_at TEXT DEFAULT (datetime('now','localtime')));
CREATE TABLE IF NOT EXISTS approval_rules (
  id INTEGER PRIMARY KEY, leave_type TEXT UNIQUE NOT NULL, label TEXT NOT NULL,
  auto_approve INTEGER NOT NULL DEFAULT 0, max_days INTEGER, active INTEGER NOT NULL DEFAULT 1);
CREATE TABLE IF NOT EXISTS notifications (   -- sekaligus outbox
  id INTEGER PRIMARY KEY, employee_id INTEGER NOT NULL DEFAULT 0, phone TEXT, message TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'QUEUED', attempts INTEGER NOT NULL DEFAULT 0, created_at TEXT DEFAULT (datetime('now','localtime')));
CREATE INDEX IF NOT EXISTS idx_notif_status ON notifications(status);
CREATE TABLE IF NOT EXISTS audit_logs (
  id INTEGER PRIMARY KEY, actor TEXT NOT NULL, action TEXT NOT NULL, entity TEXT, entity_id INTEGER, detail TEXT,
  created_at TEXT DEFAULT (datetime('now','localtime')));
CREATE TABLE IF NOT EXISTS counters (name TEXT PRIMARY KEY, value INTEGER NOT NULL);
`);
if (!db.prepare('PRAGMA table_info(employees)').all().some((c) => c.name === 'active'))
  db.exec('ALTER TABLE employees ADD COLUMN active INTEGER NOT NULL DEFAULT 1');

const LR = (n) => `CREATE TABLE ${n} (
  id INTEGER PRIMARY KEY, request_no TEXT UNIQUE, employee_id INTEGER,
  applicant_name TEXT NOT NULL, applicant_nik TEXT NOT NULL, applicant_position TEXT NOT NULL, department TEXT NOT NULL, phone TEXT,
  leave_type TEXT NOT NULL, start_date TEXT NOT NULL, end_date TEXT NOT NULL, reason TEXT NOT NULL, status TEXT NOT NULL, reject_reason TEXT,
  version INTEGER NOT NULL DEFAULT 1,            -- optimistic locking
  created_at TEXT DEFAULT (datetime('now','localtime')), updated_at TEXT DEFAULT (datetime('now','localtime')))`;
const lrCols = db.prepare('PRAGMA table_info(leave_requests)').all();
if (!lrCols.length) db.exec(LR('leave_requests'));
else if (!lrCols.some((c) => c.name === 'department')) { // migrasi database lama
  db.pragma('foreign_keys = OFF');
  db.transaction(() => {
    db.exec(LR('leave_requests_new'));
    db.exec(`INSERT INTO leave_requests_new(id,request_no,employee_id,applicant_name,applicant_nik,applicant_position,department,phone,leave_type,start_date,end_date,reason,status,reject_reason,version,created_at,updated_at)
      SELECT r.id,r.request_no,r.employee_id,e.name,e.nik,COALESCE(p.name,'-'),COALESCE(d.name,'HRGA'),e.phone,r.leave_type,r.start_date,r.end_date,r.reason,r.status,r.reject_reason,r.version,r.created_at,r.updated_at
      FROM leave_requests r JOIN employees e ON e.id=r.employee_id LEFT JOIN departments d ON d.id=e.department_id LEFT JOIN positions p ON p.id=e.position_id`);
    db.exec('DROP TABLE leave_requests'); db.exec('ALTER TABLE leave_requests_new RENAME TO leave_requests');
  })();
  db.pragma('foreign_keys = ON');
}
// kunci pribadi pemohon (hash) -> riwayat hanya bisa dibuka oleh pemilik kunci
if (!db.prepare('PRAGMA table_info(leave_requests)').all().some((c) => c.name === 'owner_hash'))
  db.exec('ALTER TABLE leave_requests ADD COLUMN owner_hash TEXT');
db.exec('CREATE INDEX IF NOT EXISTS idx_lr_owner ON leave_requests(owner_hash)');
db.exec(`CREATE INDEX IF NOT EXISTS idx_lr_dept ON leave_requests(department, status);
  CREATE INDEX IF NOT EXISTS idx_lr_nik ON leave_requests(applicant_nik);
  CREATE INDEX IF NOT EXISTS idx_lr_status ON leave_requests(status);`);

const hash = (pw) => { const s = crypto.randomBytes(16).toString('hex');
  return s + ':' + crypto.scryptSync(pw, s, 32).toString('hex'); };
const verify = (pw, h) => { const [s, k] = h.split(':');
  return crypto.timingSafeEqual(Buffer.from(k, 'hex'), crypto.scryptSync(pw, s, 32)); };

if (!db.prepare('SELECT 1 FROM users LIMIT 1').get()) {
  db.transaction(() => {
    const emp = db.prepare('INSERT INTO employees(nik,name,phone) VALUES (?,?,?)');
    const usr = db.prepare('INSERT INTO users(username,password_hash,role,employee_id) VALUES (?,?,?,?)');
    const pw = hash('password123');
    const budi = usr.run('budi', pw, 'SUPERVISOR', emp.run('USR-BUDI', 'Budi Supervisor', '6281200000001').lastInsertRowid).lastInsertRowid;
    usr.run('rina', pw, 'HR', emp.run('USR-RINA', 'Rina HR', '6281200000004').lastInsertRowid);
    usr.run('admin', pw, 'ADMIN', emp.run('A001', 'Admin Sistem', '6281200000005').lastInsertRowid);
    DEPARTMENTS.forEach((d) => db.prepare('INSERT INTO dept_supervisors VALUES (?,?)').run(d, budi)); // demo: Budi mengawasi semua departemen
    const rule = db.prepare('INSERT INTO approval_rules(leave_type,label,auto_approve,max_days) VALUES (?,?,?,?)');
    rule.run('KELUAR_SITE_PRIBADI', 'Keluar Site - Keperluan Pribadi', 1, 3);
    rule.run('SAKIT', 'Sakit', 1, 5);
    rule.run('CUTI_TAHUNAN', 'Cuti Tahunan', 1, 12);
    rule.run('IZIN_KHUSUS', 'Izin Khusus (review manual HR)', 0, null);
  })();
}
// database lama: atasan yang sudah ada diberi semua departemen sekali saja (admin bisa mengubah)
if (!db.prepare("SELECT 1 FROM counters WHERE name='migr-dept'").get()) {
  db.transaction(() => {
    db.prepare("SELECT id FROM users WHERE role='SUPERVISOR'").all().forEach((u) =>
      DEPARTMENTS.forEach((d) => db.prepare('INSERT OR IGNORE INTO dept_supervisors VALUES (?,?)').run(d, u.id)));
    db.prepare("INSERT INTO counters(name,value) VALUES ('migr-dept',1)").run();
  })();
}
// pastikan akun admin ada; reset=true -> password kembali ke password123
function ensureAdmin(reset = false) {
  db.transaction(() => {
    db.prepare("INSERT OR IGNORE INTO employees(nik,name,phone) VALUES ('A001','Admin Sistem','6281200000005')").run();
    const eid = db.prepare("SELECT id FROM employees WHERE nik='A001'").get().id;
    const u = db.prepare("SELECT id FROM users WHERE username='admin'").get();
    if (!u) db.prepare("INSERT INTO users(username,password_hash,role,employee_id) VALUES ('admin',?,'ADMIN',?)").run(hash('password123'), eid);
    else if (reset) {
      db.prepare("UPDATE users SET password_hash=?, role='ADMIN', employee_id=? WHERE id=?").run(hash('password123'), eid, u.id);
      db.prepare('UPDATE employees SET active=1 WHERE id=?').run(eid);
    }
  })();
}
if (!db.prepare("SELECT 1 FROM users WHERE role='ADMIN'").get()) ensureAdmin();
module.exports = { db, hash, verify, ensureAdmin, DEPARTMENTS };
