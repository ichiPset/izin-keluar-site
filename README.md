# Aplikasi Izin Keluar Site

Alur: **Karyawan → Atasan → Auto Approval Engine (SYSTEM_HR) → HR Panel**

## Menjalankan di VS Code
1. Pasang Node.js 22.13 atau lebih baru (memakai SQLite bawaan Node, tidak perlu Visual Studio/kompilasi).
2. Buka folder ini di VS Code, lalu buka Terminal.
3. `npm install`
4. (Opsional) salin `.env.example` ke `.env`, isi `WA_API_URL` dan `WA_API_TOKEN` (`node --env-file=.env src/server.js`).
   Tanpa itu, pesan WA dicetak di console. Logika kirim ada di `src/sendWA.js`.
5. `npm start` lalu buka http://localhost:3000

**Pemohon tidak perlu login dan tidak perlu didaftarkan admin**: buka halaman awal, isi nama, jabatan, NIK, departemen, No. WA,
lalu kirim. Pengajuan otomatis masuk ke atasan yang ditugaskan untuk departemen tersebut. Riwayat/status dilihat dengan NIK + nama.
Tidak ada pengecekan overlap tanggal.

Petugas login lewat tautan *Login Petugas* (password `password123`): `budi` (atasan), `rina` (HR), `admin` (admin).
Admin hanya mengelola akun petugas (Atasan/HR/Admin), departemen yang diawasi tiap atasan, dan rule persetujuan.
Lupa password admin: `node src/reset-admin.js`. Database lama dimigrasi otomatis saat server dijalankan.

## Status
PENDING_SUPERVISOR → APPROVED_ATASAN → AUTO_APPROVED_HR | PENDING_HR_MANUAL → APPROVED_HR
Penolakan di tahap mana pun → REJECTED (alasan wajib).

## Concurrency & stabilitas
- **Optimistic locking**: kolom `version`; UPDATE hanya sukses jika `version` dan `status` masih sama,
  sehingga double approve menghasilkan HTTP 409.
- **Transaksi atomik**: setiap perubahan status + log audit + notifikasi disimpan dalam satu transaksi.
- **Event + idempotent engine**: engine hanya memproses status `APPROVED_ATASAN`; saat server restart,
  pengajuan yang tertinggal diproses ulang (`recover()`).
- **Outbox notifikasi**: pesan disimpan dulu di tabel `notifications`, dikirim worker dengan retry maks 5x,
  sehingga WA lambat/gagal tidak menghambat proses persetujuan.
- SQLite mode WAL + busy_timeout, indeks pada tanggal dan status.

## Naik skala (ratusan–ribuan pengguna)
Ganti SQLite → PostgreSQL (skema sudah standar; gunakan `SELECT ... FOR UPDATE` bila perlu),
EventEmitter → Redis/BullMQ atau RabbitMQ, jalankan beberapa instance di belakang Nginx,
lampiran → S3/MinIO, login → SSO/AD perusahaan, tambahkan rate-limit & HTTPS.
Rule auto-approve dapat diubah di tabel `approval_rules` (auto_approve, max_days).

## Struktur
src/db.js (skema + seed) · src/server.js (API, engine, worker WA) · public/index.html (UI 3 peran)

## Catatan
- Tidak ada lampiran/file yang disimpan; database hanya mencatat data pengajuan, approval (`request_approvals`), notifikasi, dan `audit_logs`.
- Surat persetujuan PDF dibuat saat diunduh (tombol ⬇ PDF) dan tidak disimpan di server.
- Admin Panel: tambah/ubah rule (auto-approve, maks hari, aktif/nonaktif).
- Lupa/tidak bisa login admin: jalankan `node src/reset-admin.js` (password kembali ke `password123`).

## Alur terbaru
- Pemohon tidak didaftarkan dan tidak login. Wajib isi: nama lengkap, jabatan, NIK, departemen (HRGA, MINING, PLAN, HSE, LOGISTIK, VENDOR, VISITOR).
- Pengajuan otomatis masuk ke Supervisor Panel atasan yang ditugaskan admin untuk departemen tersebut (tab *Atasan & HR*).
- Overlap tanggal tidak lagi dicek. Riwayat pemohon dilihat dengan NIK + nama yang cocok.
- Demo: atasan `budi` mengawasi semua departemen; ubah di Admin Panel.
- Rate limit per IP: `RATE_LIMIT` (default 300 permintaan/menit untuk halaman publik) dan 30/menit untuk login. Jika di belakang Nginx/proxy, tambahkan `app.set('trust proxy', 1)` di `src/server.js`.
- Admin dapat menambah, mengubah, dan menghapus akun Atasan/HR/Admin. Atasan satu-satunya sebuah departemen tidak bisa dihapus selama ada pengajuan yang menunggu.
- **Riwayat pribadi**: pemohon mendapat kunci acak di browsernya (hanya hash yang disimpan di server). Riwayat & unduh PDF hanya bisa dibuka dengan kunci itu; kode akses bisa disalin untuk perangkat lain.
- **Log per pengajuan** (tombol 📜 Log) tersimpan di `audit_logs` dan terlihat oleh atasan departemen terkait, HR, dan admin.
- Surat PDF: kop berwarna, nama perusahaan di bawah judul, tabel data, riwayat persetujuan, stempel DISETUJUI.
