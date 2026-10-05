// Satu-satunya titik pengiriman WhatsApp. Ganti isi fungsi ini bila gateway Anda berbeda.
// Default: HTTP POST {target, message} (kompatibel dengan Fonnte dan banyak gateway WA lain).
module.exports = async function sendWA(phone, message) {
  const url = process.env.WA_API_URL;
  if (!url) return console.log(`[WA-SIMULASI] ke ${phone}: ${message}`);
  const r = await fetch(url, {
    method: 'POST',
    headers: { Authorization: process.env.WA_API_TOKEN || '', 'Content-Type': 'application/json' },
    body: JSON.stringify({ target: phone, message }),
  });
  if (!r.ok) throw new Error('WA gagal ' + r.status);
};
