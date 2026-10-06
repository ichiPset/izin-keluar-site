require('express-async-errors');
const express = require('express');
const crypto = require('crypto');
const path = require('path');
const PDFDocument = require('pdfkit');
const { EventEmitter } = require('events');
const { db, initDb, verify, hash, DEPARTMENTS } = require('./db');
const sendWA = require('./sendWA');

// BigInt serializer untuk Turso (wajib agar JSON.stringify tidak error)
BigInt.prototype.toJSON = function () { return Number(this); };

const SECRET = process.env.APP_SECRET;
if (!SECRET) {
  console.error('FATAL: APP_SECRET belum diisi!');
  process.exit(1);
}

const bus = new EventEmitter();
const app = express();
app.set('trust proxy', 1);
app.use(express.json());
app.use(express.static(path.join(__dirname, '../public'), { setHeaders: (res) => res.setHeader('Cache-Control', 'no-cache') }));

// ---------- util ----------
const today = () => new Date().toLocaleDateString('sv-SE');
const days = (a, b) => Math.round((new Date(b) - new Date(a)) / 864e5) + 1;
const clean = (v, n = 100) => String(v || '').trim().replace(/\s+/g, ' ').slice(0, n);
const normNik = (v) => String(v || '').trim().toUpperCase();
const normPhone = (p) => { p = String(p || '').replace(/\D/g, ''); return p.startsWith('0') ? '62' + p.slice(1) : p; };
const sha = (v) => crypto.createHash('sha256').update(String(v || '')).digest('hex');
const validKey = (k) => /^[a-f0-9]{32}$/.test(String(k || ''));
const bad = (m, code = 400) => Object.assign(new Error(m), { code });
const st = (e) => (Number.isInteger(e.code) ? e.code : 500);

// Async Helpers untuk Turso
const dbGet = async (sql, args = []) => (await db.execute({ sql, args })).rows[0];
const dbAll = async (sql, args = []) => (await db.execute({ sql, args })).rows;
const dbRun = async (sql, args = []) => await db.execute({ sql, args });

const audit = async (actor, action, entity, id, detail) =>
  await dbRun('INSERT INTO audit_logs(actor,action,entity,entity_id,detail) VALUES (?,?,?,?,?)', [actor, action, entity, id, detail ? JSON.stringify(detail) : null]);

const notifyPhone = async (phone, message) => {
  if (phone) await dbRun('INSERT INTO notifications(employee_id,phone,message) VALUES (0,?,?)', [phone, message]);
};

const notify = async (eid, message) => {
  const e = await dbGet('SELECT phone FROM employees WHERE id=?', [eid]);
  await notifyPhone(e && e.phone, message);
};

const notifyHR = async (msg) => {
  const hrs = await dbAll("SELECT employee_id FROM users WHERE role='HR'");
  for (const u of hrs) await notify(u.employee_id, msg);
};

const nextNumber = async () => {
  const ym = today().slice(0, 7), key = 'izin-' + ym;
  await dbRun('INSERT INTO counters(name,value) VALUES (?,1) ON CONFLICT(name) DO UPDATE SET value=value+1', [key]);
  const row = await dbGet('SELECT value FROM counters WHERE name=?', [key]);
  return `IZN/${ym.replace('-', '/')}/${String(row.value).padStart(5, '0')}`;
};

const hits = new Map();
const bucket = (max) => (req, res, next) => {
  const k = req.ip + ':' + max, t = Date.now(), a = (hits.get(k) || []).filter((x) => t - x < 60000);
  if (a.length >= max) return res.status(429).json({ error: 'Terlalu banyak permintaan, coba lagi sebentar' });
  a.push(t); hits.set(k, a); next();
};
const limit = bucket(+process.env.RATE_LIMIT || 300);
const loginLimit = bucket(30);
setInterval(() => hits.clear(), 600000).unref();

// ---------- auth ----------
const sign = (p) => {
  const b = Buffer.from(JSON.stringify(p)).toString('base64url');
  return b + '.' + crypto.createHmac('sha256', SECRET).update(b).digest('base64url');
};

const auth = (...roles) => (req, res, next) => {
  const [b, sig] = (req.headers.authorization || '').replace('Bearer ', '').split('.');
  if (!b || !sig || crypto.createHmac('sha256', SECRET).update(b).digest('base64url') !== sig)
    return res.status(401).json({ error: 'Belum login' });
  const p = JSON.parse(Buffer.from(b, 'base64url'));
  if (p.exp < Date.now()) return res.status(401).json({ error: 'Sesi habis' });
  if (roles.length && !roles.includes(p.role)) return res.status(403).json({ error: 'Tidak punya akses' });
  req.user = p; next();
};

// ---------- ROUTES ----------
app.post('/api/login', loginLimit, async (req, res) => {
  const u = await dbGet('SELECT u.*, e.name FROM users u JOIN employees e ON e.id=u.employee_id WHERE username=? AND e.active=1', [String(req.body.username || '').trim().toLowerCase()]);
  if (!u || !verify(String(req.body.password || ''), u.password_hash)) return res.status(401).json({ error: 'Username/password salah' });
  const user = { uid: Number(u.id), eid: Number(u.employee_id), role: u.role, name: u.name, exp: Date.now() + 12 * 3600e3 };
  res.json({ token: sign(user), user });
});

app.get('/api/public/meta', limit, async (_, res) => res.json({ departments: DEPARTMENTS, rules: await dbAll('SELECT leave_type,label FROM approval_rules WHERE active=1') }));

app.post('/api/public/requests', limit, async (req, res) => {
  const b = req.body, name = clean(b.name), nik = normNik(b.nik), position = clean(b.position), department = String(b.department || '').toUpperCase(),
    phone = normPhone(b.phone), leave_type = String(b.leave_type || ''), start_date = String(b.start_date || ''), end_date = String(b.end_date || ''),
    reason = String(b.reason || '').trim(), D = /^\d{4}-\d{2}-\d{2}$/;
  const fail = (m) => res.status(400).json({ error: m });
  if (!validKey(b.owner_key)) return fail('Sesi browser tidak valid. Muat ulang halaman lalu coba lagi.');
  if (!name || !nik || !position || !department) return fail('Nama lengkap, jabatan, NIK, dan departemen wajib diisi');
  if (!/^[A-Z0-9._-]{3,30}$/.test(nik)) return fail('NIK tidak valid');
  if (!DEPARTMENTS.includes(department)) return fail('Departemen tidak valid');
  if (phone && !/^\d{9,15}$/.test(phone)) return fail('No. WhatsApp tidak valid');
  if (!leave_type || !D.test(start_date) || !D.test(end_date) || !reason) return fail('Semua field wajib diisi');
  if (reason.length > 500) return fail('Alasan maksimal 500 karakter');
  if (!(await dbGet('SELECT 1 FROM approval_rules WHERE leave_type=? AND active=1', [leave_type]))) return fail('Jenis izin tidak valid');
  if (start_date < today()) return fail('Tanggal mulai tidak boleh mundur');
  if (end_date < start_date) return fail('Tanggal selesai sebelum tanggal mulai');
  const sups = await dbAll(`SELECT DISTINCT u.employee_id eid FROM dept_supervisors ds JOIN users u ON u.id=ds.user_id JOIN employees e ON e.id=u.employee_id WHERE ds.department=? AND u.role='SUPERVISOR' AND e.active=1`, [department]);
  if (!sups.length) return fail(`Belum ada atasan untuk departemen ${department}. Hubungi admin.`);
  try {
    let newId = null;
    await db.transaction(async (tx) => {
      const idRes = await tx.execute({
        sql: `INSERT INTO leave_requests(applicant_name,applicant_nik,applicant_position,department,phone,leave_type,start_date,end_date,reason,status,owner_hash) VALUES (?,?,?,?,?,?,?,?,?,'PENDING_SUPERVISOR',?)`,
        args: [name, nik, position, department, phone || null, leave_type, start_date, end_date, reason, sha(b.owner_key)]
      });
      newId = Number(idRes.lastInsertRowid);
      await tx.execute({ sql: 'INSERT INTO audit_logs(actor,action,entity,entity_id,detail) VALUES (?,?,?,?,?)', args: [name, 'SUBMIT', 'leave_request', newId, JSON.stringify({ nik, department })] });
      for (const s of sups) {
        const e = await tx.execute({ sql: 'SELECT phone FROM employees WHERE id=?', args: [Number(s.eid)] });
        if (e.rows[0] && e.rows[0].phone) {
          await tx.execute({ sql: 'INSERT INTO notifications(employee_id,phone,message) VALUES (0,?,?)', args: [e.rows[0].phone, `[Izin] ${name} (${department}) mengajukan izin ${start_date} s/d ${end_date}. Mohon review di Supervisor Panel.`] });
        }
      }
    });
    res.status(201).json({ id: newId, status: 'PENDING_SUPERVISOR' });
  } catch (e) { res.status(st(e)).json({ error: e.message }); }
});

app.post('/api/public/history', limit, async (req, res) => {
  if (!validKey(req.body.owner_key)) return res.json([]);
  res.json(await dbAll(`SELECT id,request_no,applicant_name,applicant_nik,applicant_position,department,leave_type,start_date,end_date,reason,status,reject_reason,version,created_at,updated_at FROM leave_requests WHERE owner_hash=? ORDER BY id DESC LIMIT 100`, [sha(req.body.owner_key)]));
});

// ---------- SUPERVISOR ----------
const MYDEPT = 'department IN (SELECT department FROM dept_supervisors WHERE user_id=?)';

app.get('/api/supervisor/requests', auth('SUPERVISOR'), async (req, res) => {
  const rows = await dbAll(`SELECT * FROM leave_requests WHERE ${MYDEPT} ORDER BY CASE WHEN status='PENDING_SUPERVISOR' THEN 0 ELSE 1 END, id DESC LIMIT 200`, [req.user.uid]);
  res.json(rows);
});

app.post('/api/supervisor/requests/:id/decision', auth('SUPERVISOR'), async (req, res) => {
  const { action, version, note } = req.body, id = +req.params.id;
  if (!['APPROVE', 'REJECT'].includes(action)) return res.status(400).json({ error: 'Aksi tidak valid' });
  if (action === 'REJECT' && !String(note || '').trim()) return res.status(400).json({ error: 'Alasan penolakan wajib diisi' });
  try {
    let r;
    await db.transaction(async (tx) => {
      const q = await tx.execute({ sql: `SELECT * FROM leave_requests WHERE id=? AND ${MYDEPT}`, args: [id, req.user.uid] });
      r = q.rows[0];
      if (!r) throw bad('Pengajuan bukan dari departemen Anda', 403);
      const uq = await tx.execute({
        sql: `UPDATE leave_requests SET status=?, reject_reason=?, version=version+1, updated_at=datetime('now','localtime') WHERE id=? AND version=? AND status='PENDING_SUPERVISOR'`,
        args: [action === 'APPROVE' ? 'APPROVED_ATASAN' : 'REJECTED', action === 'REJECT' ? note.trim() : null, id, Number(version)]
      });
      if (uq.rowsAffected === 0) throw bad('Data sudah diproses/berubah. Muat ulang halaman.', 409);
      await tx.execute({ sql: 'INSERT INTO request_approvals(request_id,level,approver,action,note) VALUES (?,?,?,?,?)', args: [id, 'SUPERVISOR', req.user.name, action, note || null] });
      await tx.execute({ sql: 'INSERT INTO audit_logs(actor,action,entity,entity_id,detail) VALUES (?,?,?,?,?)', args: [req.user.name, action, 'leave_request', id, JSON.stringify({ note })] });
      if (action === 'REJECT' && r.phone) {
        await tx.execute({ sql: 'INSERT INTO notifications(employee_id,phone,message) VALUES (0,?,?)', args: [r.phone, `[Izin] Pengajuan ${r.start_date} s/d ${r.end_date} DITOLAK atasan. Alasan: ${note.trim()}`] });
      }
    });
    if (action === 'APPROVE') await processApproval(id); // Jalankan langsung, jangan via event
res.json({ ok: true });
  } catch (e) { res.status(st(e)).json({ error: e.message }); }
});

// ---------- AUTO APPROVAL ENGINE ----------
async function processApproval(id) {
  try {
    await db.transaction(async (tx) => {
      const q = await tx.execute({ sql: "SELECT * FROM leave_requests WHERE id=? AND status='APPROVED_ATASAN'", args: [id] });
      const r = q.rows[0]; if (!r) return; // idempotent
      const rq = await tx.execute({ sql: 'SELECT * FROM approval_rules WHERE leave_type=? AND active=1', args: [r.leave_type] });
      const rule = rq.rows[0];
      if (rule && rule.auto_approve && (!rule.max_days || days(r.start_date, r.end_date) <= rule.max_days)) {
        const ym = today().slice(0, 7), key = 'izin-' + ym;
        await tx.execute({ sql: 'INSERT INTO counters(name,value) VALUES (?,1) ON CONFLICT(name) DO UPDATE SET value=value+1', args: [key] });
        const cRow = await tx.execute({ sql: 'SELECT value FROM counters WHERE name=?', args: [key] });
        const no = `IZN/${ym.replace('-', '/')}/${String(cRow.rows[0].value).padStart(5, '0')}`;
        await tx.execute({ sql: `UPDATE leave_requests SET status='AUTO_APPROVED_HR', request_no=?, version=version+1, updated_at=datetime('now','localtime') WHERE id=?`, args: [no, id] });
        await tx.execute({ sql: 'INSERT INTO request_approvals(request_id,level,approver,action,note) VALUES (?,?,?,?,?)', args: [id, 'HR', 'SYSTEM_HR', 'AUTO_APPROVE', 'Memenuhi rule auto-approve'] });
        await tx.execute({ sql: 'INSERT INTO audit_logs(actor,action,entity,entity_id,detail) VALUES (?,?,?,?,?)', args: ['SYSTEM_HR', 'AUTO_APPROVE', 'leave_request', id, JSON.stringify({ no })] });
        if (r.phone) await tx.execute({ sql: 'INSERT INTO notifications(employee_id,phone,message) VALUES (0,?,?)', args: [r.phone, `[Izin] Izin DISETUJUI. No: ${no} (${r.start_date} s/d ${r.end_date}).`] });
      } else {
        await tx.execute({ sql: `UPDATE leave_requests SET status='PENDING_HR_MANUAL', version=version+1, updated_at=datetime('now','localtime') WHERE id=?`, args: [id] });
        await tx.execute({ sql: 'INSERT INTO audit_logs(actor,action,entity,entity_id,detail) VALUES (?,?,?,?,?)', args: ['SYSTEM_HR', 'ESCALATE_MANUAL', 'leave_request', id, null] });
        const hrs = await tx.execute("SELECT employee_id FROM users WHERE role='HR'");
        for (const u of hrs.rows) {
          const e = await tx.execute({ sql: 'SELECT phone FROM employees WHERE id=?', args: [Number(u.employee_id)] });
          if (e.rows[0] && e.rows[0].phone) await tx.execute({ sql: 'INSERT INTO notifications(employee_id,phone,message) VALUES (0,?,?)', args: [e.rows[0].phone, `[Izin] Pengajuan #${id} (${r.applicant_name}, ${r.department}) perlu review manual HR.`] });
        }
        if (r.phone) await tx.execute({ sql: 'INSERT INTO notifications(employee_id,phone,message) VALUES (0,?,?)', args: [r.phone, '[Izin] Pengajuan Anda disetujui atasan, menunggu review HR.'] });
      }
    });
  } catch (e) { console.error('Engine error', e); }
}

const recover = async () => {
  const rows = await dbAll("SELECT id FROM leave_requests WHERE status='APPROVED_ATASAN'");
  for (const r of rows) await processApproval(Number(r.id));
};

// ---------- HR ----------
app.get('/api/hr/requests', auth('HR'), async (req, res) => {
  const rows = await dbAll("SELECT * FROM leave_requests ORDER BY CASE WHEN status='PENDING_HR_MANUAL' THEN 0 ELSE 1 END, id DESC LIMIT 300");
  res.json(rows);
});

app.post('/api/hr/requests/:id/decision', auth('HR'), async (req, res) => {
  const { action, version, note } = req.body, id = +req.params.id;
  if (!['APPROVE', 'REJECT'].includes(action)) return res.status(400).json({ error: 'Aksi tidak valid' });
  if (action === 'REJECT' && !String(note || '').trim()) return res.status(400).json({ error: 'Alasan penolakan wajib diisi' });
  try {
    let r;
    await db.transaction(async (tx) => {
      const q = await tx.execute({ sql: 'SELECT * FROM leave_requests WHERE id=?', args: [id] });
      r = q.rows[0]; if (!r) throw bad('Tidak ditemukan', 404);
      const ok = action === 'APPROVE';
      let no = null;
      if (ok) {
        const ym = today().slice(0, 7), key = 'izin-' + ym;
        await tx.execute({ sql: 'INSERT INTO counters(name,value) VALUES (?,1) ON CONFLICT(name) DO UPDATE SET value=value+1', args: [key] });
        const cRow = await tx.execute({ sql: 'SELECT value FROM counters WHERE name=?', args: [key] });
        no = `IZN/${ym.replace('-', '/')}/${String(cRow.rows[0].value).padStart(5, '0')}`;
      }
      const uq = await tx.execute({
        sql: `UPDATE leave_requests SET status=?, request_no=?, reject_reason=?, version=version+1, updated_at=datetime('now','localtime') WHERE id=? AND version=? AND status='PENDING_HR_MANUAL'`,
        args: [ok ? 'APPROVED_HR' : 'REJECTED', no, ok ? null : note.trim(), id, Number(version)]
      });
      if (uq.rowsAffected === 0) throw bad('Data sudah diproses/berubah. Muat ulang halaman.', 409);
      await tx.execute({ sql: 'INSERT INTO request_approvals(request_id,level,approver,action,note) VALUES (?,?,?,?,?)', args: [id, 'HR', req.user.name, action, note || null] });
      await tx.execute({ sql: 'INSERT INTO audit_logs(actor,action,entity,entity_id,detail) VALUES (?,?,?,?,?)', args: [req.user.name, 'HR_' + action, 'leave_request', id, JSON.stringify({ note })] });
      if (r.phone) await tx.execute({ sql: 'INSERT INTO notifications(employee_id,phone,message) VALUES (0,?,?)', args: [r.phone, ok ? `[Izin] Izin DISETUJUI HR. No: ${no}` : `[Izin] Izin DITOLAK HR. Alasan: ${note.trim()}`] });
    });
    res.json({ ok: true });
  } catch (e) { res.status(st(e)).json({ error: e.message }); }
});

app.get('/api/audit', auth('HR', 'ADMIN'), async (_, res) => res.json(await dbAll('SELECT * FROM audit_logs ORDER BY id DESC LIMIT 100')));

// ---------- ADMIN: RULES ----------
app.get('/api/admin/rules', auth('ADMIN'), async (_, res) => res.json(await dbAll('SELECT * FROM approval_rules ORDER BY id')));

app.post('/api/admin/rules', auth('ADMIN'), async (req, res) => {
  const { leave_type, label, auto_approve, max_days, active } = req.body;
  if (!/^[A-Z0-9_]{3,40}$/.test(leave_type || '') || !String(label || '').trim()) return res.status(400).json({ error: 'Kode (A-Z, 0-9, _) dan nama wajib diisi' });
  const md = max_days ? Math.max(1, parseInt(max_days, 10)) : null;
  await dbRun(`INSERT INTO approval_rules(leave_type,label,auto_approve,max_days,active) VALUES (?,?,?,?,?) ON CONFLICT(leave_type) DO UPDATE SET label=excluded.label, auto_approve=excluded.auto_approve, max_days=excluded.max_days, active=excluded.active`, [leave_type, label.trim(), auto_approve ? 1 : 0, md, active ? 1 : 0]);
  await audit(req.user.name, 'RULE_SAVE', 'approval_rule', null, { leave_type, auto_approve, max_days: md, active });
  res.json({ ok: true });
});

// ---------- ADMIN: USERS ----------
app.get('/api/admin/users', auth('ADMIN'), async (_, res) => {
  res.json(await dbAll(`SELECT u.id user_id, e.name, e.phone, e.active, u.username, u.role, (SELECT group_concat(department) FROM dept_supervisors WHERE user_id=u.id) depts FROM users u JOIN employees e ON e.id=u.employee_id ORDER BY e.name`));
});

app.post('/api/admin/users', auth('ADMIN'), async (req, res) => {
  const b = req.body, uid = b.user_id ? +b.user_id : null, active = (b.active === false || b.active === 0) ? 0 : 1;
  const name = clean(b.name), role = String(b.role || ''), username = String(b.username || '').trim().toLowerCase(), pw = String(b.password || '');
  const depts = [...new Set((Array.isArray(b.departments) ? b.departments : []).filter((d) => DEPARTMENTS.includes(d)))];
  try {
    if (!name) throw bad('Nama wajib diisi');
    if (!['SUPERVISOR', 'HR', 'ADMIN'].includes(role)) throw bad('Akses tidak valid');
    if (!/^[a-z0-9._-]{3,30}$/.test(username)) throw bad('Username 3-30 karakter (huruf kecil/angka)');
    if (role === 'SUPERVISOR' && !depts.length) throw bad('Pilih minimal satu departemen untuk atasan');
    if (uid && uid === req.user.uid && (role !== 'ADMIN' || !active)) throw bad('Akun admin Anda sendiri tidak boleh diturunkan/dinonaktifkan');

    await db.transaction(async (tx) => {
      let id = uid;
      if (id) {
        const u = (await tx.execute({ sql: 'SELECT employee_id FROM users WHERE id=?', args: [id] })).rows[0];
        if (!u) throw bad('User tidak ditemukan', 404);
        await tx.execute({ sql: 'UPDATE employees SET name=?, phone=?, active=? WHERE id=?', args: [name, normPhone(b.phone) || null, active, Number(u.employee_id)] });
        await tx.execute({ sql: 'UPDATE users SET role=?, username=? WHERE id=?', args: [role, username, id] });
        if (pw) {
          if (pw.length < 6) throw bad('Password minimal 6 karakter');
          await tx.execute({ sql: 'UPDATE users SET password_hash=? WHERE id=?', args: [hash(pw), id] });
        }
      } else {
        if (pw.length < 6) throw bad('Password minimal 6 karakter');
        const eidRes = await tx.execute({ sql: 'INSERT INTO employees(nik,name,phone,active) VALUES (?,?,?,?)', args: ['USR-' + username.toUpperCase(), name, normPhone(b.phone) || null, active] });
        const eid = Number(eidRes.lastInsertRowid);
        const idRes = await tx.execute({ sql: 'INSERT INTO users(username,password_hash,role,employee_id) VALUES (?,?,?,?)', args: [username, hash(pw), role, eid] });
        id = Number(idRes.lastInsertRowid);
      }
      await tx.execute({ sql: 'DELETE FROM dept_supervisors WHERE user_id=?', args: [id] });
      if (role === 'SUPERVISOR') for (const d of depts) await tx.execute({ sql: 'INSERT INTO dept_supervisors VALUES (?,?)', args: [d, id] });
      await tx.execute({ sql: 'INSERT INTO audit_logs(actor,action,entity,entity_id,detail) VALUES (?,?,?,?,?)', args: [req.user.name, uid ? 'USER_UPDATE' : 'USER_CREATE', 'user', id, JSON.stringify({ username, role, depts, active })] });
    });
    res.json({ ok: true });
  } catch (e) {
    const dup = /UNIQUE/i.test(e.message);
    res.status(dup ? 409 : st(e)).json({ error: dup ? 'Username sudah dipakai' : e.message });
  }
});

app.delete('/api/admin/users/:id', auth('ADMIN'), async (req, res) => {
  const id = +req.params.id;
  try {
    if (id === req.user.uid) throw bad('Akun Anda sendiri tidak boleh dihapus');
    await db.transaction(async (tx) => {
      const u = (await tx.execute({ sql: 'SELECT u.id, u.role, u.username, u.employee_id FROM users u WHERE u.id=?', args: [id] })).rows[0];
      if (!u) throw bad('User tidak ditemukan', 404);
      if (u.role === 'ADMIN' && (await tx.execute({ sql: "SELECT 1 FROM users WHERE role='ADMIN' AND id<>?", args: [id] })).rows.length === 0) throw bad('Admin terakhir tidak boleh dihapus');
      if (u.role === 'SUPERVISOR') {
        const ds = (await tx.execute({ sql: 'SELECT department FROM dept_supervisors WHERE user_id=?', args: [id] })).rows;
        for (const row of ds) {
          const d = row.department;
          const other = (await tx.execute({ sql: `SELECT 1 FROM dept_supervisors ds JOIN users x ON x.id=ds.user_id JOIN employees e ON e.id=x.employee_id WHERE ds.department=? AND ds.user_id<>? AND x.role='SUPERVISOR' AND e.active=1`, args: [d, id] })).rows;
          const pend = (await tx.execute({ sql: "SELECT COUNT(*) c FROM leave_requests WHERE department=? AND status='PENDING_SUPERVISOR'", args: [d] })).rows[0].c;
          if (!other.length && Number(pend) > 0) throw bad(`Departemen ${d} masih punya ${pend} pengajuan menunggu dan tidak ada atasan lain. Tunjuk atasan pengganti dulu.`, 409);
        }
      }
      await tx.execute({ sql: 'DELETE FROM dept_supervisors WHERE user_id=?', args: [id] });
      await tx.execute({ sql: 'DELETE FROM users WHERE id=?', args: [id] });
      await tx.execute({ sql: 'DELETE FROM employees WHERE id=?', args: [Number(u.employee_id)] });
      await tx.execute({ sql: 'INSERT INTO audit_logs(actor,action,entity,entity_id,detail) VALUES (?,?,?,?,?)', args: [req.user.name, 'USER_DELETE', 'user', id, JSON.stringify({ username: u.username, role: u.role })] });
    });
    res.json({ ok: true });
  } catch (e) { res.status(st(e)).json({ error: e.message }); }
});

// ---------- PDF ----------
async function sendPdf(res, r) {
  if (!['AUTO_APPROVED_HR', 'APPROVED_HR'].includes(r.status)) return res.status(400).json({ error: 'Izin belum disetujui sepenuhnya' });
  const ap = await dbAll('SELECT * FROM request_approvals WHERE request_id=? ORDER BY id', [r.id]);
  const rule = await dbGet('SELECT label FROM approval_rules WHERE leave_type=?', [r.leave_type]);
  res.setHeader('Content-Type', 'application/pdf');
  res.setHeader('Content-Disposition', `attachment; filename="${r.request_no.replace(/\//g, '-')}.pdf"`);
  const doc = new PDFDocument({ size: 'A4', margin: 0, info: { Title: 'Surat Izin ' + r.request_no, Author: 'PT Geopersada Mulia Abadi' } });
  doc.pipe(res);
  const W = 595.28, M = 48, CW = W - 2 * M, GREEN = '#0b6e4f', GOLD = '#c9a227', INK = '#1b2430', MUTED = '#6b7785', LINE = '#d5dbe2';
  const fmt = (v) => new Date(v + 'T00:00:00').toLocaleDateString('id-ID', { day: 'numeric', month: 'long', year: 'numeric' });
  const cut = (v, n) => { v = String(v || '-'); return v.length > n ? v.slice(0, n - 3) + '...' : v; };
  doc.rect(0, 0, W, 112).fill(GREEN); doc.rect(0, 112, W, 4).fill(GOLD);
  doc.fillColor('#ffffff').font('Helvetica-Bold').fontSize(19).text('SURAT IZIN MENINGGALKAN SITE', 0, 30, { width: W, align: 'center' });
  doc.fillColor('#e3f3ec').font('Helvetica').fontSize(13).text('PT Geopersada Mulia Abadi', 0, 58, { width: W, align: 'center' });
  doc.fillColor('#e3f3ec').fontSize(10).text('Nomor: ' + r.request_no, 0, 84, { width: W, align: 'center' });
  let y = 140;
  const section = (t) => { doc.fillColor(GREEN).font('Helvetica-Bold').fontSize(10).text(t.toUpperCase(), M, y, { characterSpacing: 1 }); y += 16; doc.moveTo(M, y).lineTo(M + CW, y).lineWidth(1).strokeColor(GREEN).stroke(); y += 10; };
  const field = (label, value, x, w) => { doc.fillColor(MUTED).font('Helvetica').fontSize(8).text(label.toUpperCase(), x, y, { width: w }); doc.fillColor(INK).font('Helvetica-Bold').fontSize(11).text(String(value || '-'), x, y + 12, { width: w }); };
  const half = CW / 2 - 8;
  section('Data Pemohon');
  field('Nama lengkap', r.applicant_name, M, half); field('NIK', r.applicant_nik, M + CW / 2 + 8, half); y += 40;
  field('Jabatan', r.applicant_position, M, half); field('Departemen', r.department, M + CW / 2 + 8, half); y += 46;
  section('Detail Izin');
  field('Jenis izin', rule ? rule.label : r.leave_type, M, half); field('Durasi', days(r.start_date, r.end_date) + ' hari', M + CW / 2 + 8, half); y += 40;
  field('Periode', fmt(r.start_date) + ' s/d ' + fmt(r.end_date), M, CW); y += 40;
  doc.fillColor(MUTED).font('Helvetica').fontSize(8).text('ALASAN', M, y);
  doc.fillColor(INK).font('Helvetica').fontSize(11).text(String(r.reason), M, y + 12, { width: CW });
  y += 12 + doc.heightOfString(String(r.reason), { width: CW }) + 24;
  section('Riwayat Persetujuan');
  const cols = [[M, 62, 'Tahap'], [M + 62, 118, 'Pejabat'], [M + 180, 100, 'Keputusan'], [M + 280, 105, 'Waktu'], [M + 385, CW - 385, 'Catatan']];
  doc.rect(M, y, CW, 20).fill('#eef3f1');
  cols.forEach(([x, w, t]) => doc.fillColor(GREEN).font('Helvetica-Bold').fontSize(9).text(t, x + 6, y + 6, { width: w - 8 }));
  y += 20;
  const LV = { SUPERVISOR: 'Atasan', HR: 'HR' }, AC = { APPROVE: 'Disetujui', AUTO_APPROVE: 'Disetujui otomatis', REJECT: 'Ditolak' };
  ap.forEach((a) => {
    const row = [LV[a.level] || a.level, cut(a.approver, 22), AC[a.action] || a.action, a.created_at, cut(a.note, 28)];
    cols.forEach(([x, w], i) => doc.fillColor(INK).font('Helvetica').fontSize(9).text(row[i], x + 6, y + 6, { width: w - 8 }));
    y += 22; doc.moveTo(M, y).lineTo(M + CW, y).lineWidth(0.5).strokeColor(LINE).stroke();
  });
  y += 28;
  doc.fillColor(INK).font('Helvetica-Bold').fontSize(10).text('Disahkan secara elektronik', M, y);
  doc.fillColor(MUTED).font('Helvetica').fontSize(9).text('Izin ini telah disetujui melalui sistem sesuai alur persetujuan di atas dan sah tanpa tanda tangan basah.', M, y + 15, { width: CW - 190 });
  doc.save(); doc.rotate(-8, { origin: [W - M - 85, y + 25] });
  doc.roundedRect(W - M - 160, y, 150, 46, 6).lineWidth(2.5).strokeColor('#1a7f4f').stroke();
  doc.fillColor('#1a7f4f').font('Helvetica-Bold').fontSize(19).text('DISETUJUI', W - M - 160, y + 14, { width: 150, align: 'center' });
  doc.restore();
  doc.moveTo(M, 796).lineTo(M + CW, 796).lineWidth(0.5).strokeColor(LINE).stroke();
  doc.fillColor(MUTED).font('Helvetica').fontSize(8).text('PT Geopersada Mulia Abadi  |  Sistem Izin Keluar Site  |  No. ' + r.request_no, M, 803, { width: CW, align: 'center' });
  doc.text('Dokumen diterbitkan otomatis oleh sistem. Dicetak: ' + new Date().toLocaleString('id-ID'), M, 815, { width: CW, align: 'center' });
  doc.end();
}

app.get('/api/requests/:id/pdf', auth('SUPERVISOR', 'HR', 'ADMIN'), async (req, res) => {
  const r = await dbGet('SELECT * FROM leave_requests WHERE id=?', [+req.params.id]);
  if (!r) return res.status(404).json({ error: 'Tidak ditemukan' });
  if (req.user.role === 'SUPERVISOR') {
    const isSup = await dbGet('SELECT 1 FROM dept_supervisors WHERE user_id=? AND department=?', [req.user.uid, r.department]);
    if (!isSup) return res.status(403).json({ error: 'Tidak punya akses' });
  }
  await sendPdf(res, r);
});

app.get('/api/public/requests/:id/pdf', limit, async (req, res) => {
  const r = await dbGet('SELECT * FROM leave_requests WHERE id=?', [+req.params.id]);
  if (!r || !validKey(req.headers['x-owner-key']) || !r.owner_hash || r.owner_hash !== sha(req.headers['x-owner-key'])) return res.status(404).json({ error: 'Tidak ditemukan' });
  await sendPdf(res, r);
});

// ---------- LOG ----------
app.get('/api/requests/:id/log', auth('SUPERVISOR', 'HR', 'ADMIN'), async (req, res) => {
  const id = +req.params.id, cols = 'id,request_no,applicant_name,department,status';
  const r = req.user.role === 'SUPERVISOR'
    ? await dbGet(`SELECT ${cols} FROM leave_requests WHERE id=? AND ${MYDEPT}`, [id, req.user.uid])
    : await dbGet(`SELECT ${cols} FROM leave_requests WHERE id=?`, [id]);
  if (!r) return res.status(404).json({ error: 'Tidak ditemukan atau bukan departemen Anda' });
  const logs = await dbAll("SELECT actor,action,detail,created_at FROM audit_logs WHERE entity='leave_request' AND entity_id=? ORDER BY id", [id]);
  res.json({ request: r, log: logs });
});

// ---------- WA WORKER ----------
let busy = false;
setInterval(async () => {
  if (busy) return; busy = true;
  try {
    const notifs = await dbAll("SELECT * FROM notifications WHERE status='QUEUED' ORDER BY id LIMIT 20");
    for (const n of notifs) {
      try { await sendWA(n.phone, n.message); await dbRun("UPDATE notifications SET status='SENT' WHERE id=?", [n.id]); }
      catch { await dbRun("UPDATE notifications SET attempts=attempts+1, status=CASE WHEN attempts+1>=5 THEN 'FAILED' ELSE 'QUEUED' END WHERE id=?", [n.id]); }
    }
  } catch (e) { console.error('WA Worker error', e); }
  busy = false;
}, 3000);

// ---------- INIT & SERVERLESS HANDLER ----------
let dbInitialized = false;
const init = async () => {
  if (!dbInitialized) {
    await initDb();
    try { await recover(); } catch (e) { console.error('Recover error', e); }
    dbInitialized = true;
  }
};

// Middleware untuk memastikan database siap sebelum memproses request
app.use(async (req, res, next) => {
  try {
    await init();
    next();
  } catch (err) {
    console.error('Gagal inisialisasi database:', err);
    res.status(500).json({ error: 'Gagal inisialisasi database: ' + err.message });
  }
});

// Error handler global
app.use((err, req, res, next) => {
  console.error('[Server Error]', err);
  res.status(500).json({ error: err.message || 'Terjadi kesalahan pada server' });
});

// Jika dijalankan lokal (bukan Vercel), pakai app.listen
if (!process.env.VERCEL) {
  const PORT = process.env.PORT || 3000;
  const server = app.listen(PORT, () => {
    console.log(`Aplikasi jalan di http://localhost:${PORT}`);
    init().catch(e => console.error('Init error', e));
  });
  const shutdown = () => {
    console.log('Menerima sinyal shutdown...');
    server.close(() => { console.log('Server ditutup.'); process.exit(0); });
  };
  process.on('SIGTERM', shutdown);
  process.on('SIGINT', shutdown);
}

// WAJIB untuk Vercel
module.exports = app;