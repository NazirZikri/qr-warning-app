// server.js
const express = require('express');
const db = require('./db');
const path = require('path');
const session = require('express-session');
const bcrypt = require('bcrypt');
const cookieParser = require('cookie-parser');
const { v4: uuidv4 } = require('uuid');

const app = express();
const PORT = 3000;

// ---------- Middleware ----------
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static('public'));

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use(session({
  secret: process.env.SESSION_SECRET || 'admin123',
  resave: false,
  saveUninitialized: true,
}));

// ---------- Helpers ----------
function extractIPs(req) {
  let rawIp =
    (req.headers['x-forwarded-for']?.split(',')[0] || '').trim() ||
    req.connection?.remoteAddress ||
    req.socket?.remoteAddress ||
    req.connection?.socket?.remoteAddress ||
    null;

  let ipv4 = null;
  let ipv6 = null;

  if (rawIp) {
    if (rawIp.startsWith('::ffff:')) {
      ipv4 = rawIp.replace('::ffff:', '');
    } else if (rawIp.includes(':')) {
      ipv6 = rawIp;
    } else {
      ipv4 = rawIp;
    }
  }

  return { ipv4, ipv6 };
}

async function ipToLocation(ipv4, ipv6) {
  try {
    const ip = ipv4 || ipv6;
    // Skip geo lookup for localhost
    if (!ip || ip === '127.0.0.1' || ip === '::1') return 'Unknown';
    // Node 18+ has global fetch. If you’re on older Node, `npm i node-fetch` and: const fetch = (...args)=>import('node-fetch').then(({default: f})=>f(...args));
    const resp = await fetch(`http://ip-api.com/json/${ip}`);
    const geo = await resp.json();
    if (geo?.status === 'success') {
      return `${geo.city}, ${geo.country} (${geo.isp})`;
    }
  } catch (e) {
    console.error('Geo lookup failed:', e.message);
  }
  return 'Unknown';
}

// ---------- Admin auth ----------
const ADMIN_HASHED_PASSWORD =
  process.env.ADMIN_HASHED_PASSWORD
  // default is bcrypt hash of "admin123" — change in production
  || '$2b$10$kDpKyr5tsj8HTZ/76TDOZ.ZCYNCsCBkep6FE2bVelJzUJtQGdhm/m';

// 🔒 Protect /admin routes
function requireLogin(req, res, next) {
  if (req.session?.loggedIn) return next();
  res.redirect('/admin/login');
}

// 🔐 Admin login routes
app.get('/admin/login', (req, res) => {
  res.render('login', { error: null });
});

app.post('/admin/login', async (req, res) => {
  const { password } = req.body;
  const ok = await bcrypt.compare(password, ADMIN_HASHED_PASSWORD);
  if (ok) {
    req.session.loggedIn = true;
    return res.redirect('/admin/scans');
  }
  return res.render('login', { error: 'Invalid password' });
});

app.get('/admin/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/admin/login'));
});

app.get('/admin/scans', requireLogin, (req, res) => {
  db.all(`SELECT * FROM scans ORDER BY datetime DESC`, (err, rows) => {
    if (err) return res.status(500).send('Error loading scans');
    res.render('admin', { scans: rows });
  });
});

// ---------- Consent route to save optional name ----------
app.post('/api/consent-name', (req, res) => {
  const { name } = req.body;
  const anonId = req.cookies.anonId;
  if (!anonId || !name?.trim()) return res.status(400).send('Missing data');

  db.run(
    `UPDATE scans
     SET user_name = ?, name_consent_at = ?
     WHERE anon_id = ?
     ORDER BY id DESC
     LIMIT 1`,
    [name.trim(), new Date().toISOString(), anonId],
    (err) => {
      if (err) return res.status(500).send('DB error');
      res.redirect('back'); // reload page
    }
  );
});

// show the report form (can prefill qr via ?q=)
app.get('/report', (req, res) => {
  const qrId = req.query.q || '';
  res.render('report', { qrId });
});

// receive form submission
app.post('/report', express.urlencoded({ extended: true }), (req, res) => {
  // anonId cookie setup ...
  let anonId = req.cookies?.anonId;
  if (!anonId) {
    const crypto = require('crypto');
    anonId = crypto.randomBytes(8).toString('hex');
    res.cookie('anonId', anonId, { maxAge: 1000 * 60 * 60 * 24 * 365 });
  }

  const { qr_link, reporter_name, reporter_email, description } = req.body;
  const created_at = new Date().toISOString();

  db.run(
    `INSERT INTO reports (anon_id, qr_link, reporter_name, reporter_email, description, created_at)
     VALUES (?, ?, ?, ?, ?, ?)`,
    [anonId, qr_link || null, reporter_name || null, reporter_email || null, description || null, created_at],
    function (err) {                               // <-- IMPORTANT: use function, NOT arrow
      if (err) {
        console.error('Report insert error:', err.message);
        return res.status(500).send('Server error');
      }
      console.log('Inserted report id =', this.lastID); // debug
      return res.redirect(`/report/thanks?id=${this.lastID}`);
    }
  );
});


// GET /report/thanks?id=NN  — show scary awareness page (no delete)
app.get('/report/thanks', (req, res) => {
  const id = parseInt(req.query.id || 0, 10);
  if (!id) return res.render('report-thanks', { note: 'No report found.', report: null });

  db.get(`SELECT * FROM reports WHERE id = ?`, [id], (err, row) => {
    if (err) {
      console.error('Fetch report error:', err?.message);
      return res.render('report-thanks', { note: 'Error loading report.', report: null });
    }
    if (!row) return res.render('report-thanks', { note: 'Report not found.', report: null });

    // Only allow the owner to see unmasked fields (still we won't allow deletion)
    const anonId = req.cookies?.anonId || null;
    const ownerView = anonId && row.anon_id && anonId === row.anon_id;

    // server-side sanitization/masking
    const mask = (s, keepLeft = 1, keepRight = 1) => {
      if (!s) return '';
      if (s.length <= keepLeft + keepRight + 2) return '***';
      return s.slice(0, keepLeft) + '***' + s.slice(s.length - keepRight);
    };

    const masked = {
      reporter_name: ownerView ? row.reporter_name : mask(row.reporter_name || '', 1, 0),
      reporter_email: ownerView ? row.reporter_email : (row.reporter_email ? row.reporter_email.replace(/(.{1})(.*)(@.*)/, (m, a, b, c) => a + '***' + c) : ''),
      qr_link: row.qr_link ? (row.qr_link.length > 200 ? row.qr_link.slice(0, 200) + '…' : row.qr_link) : '',
      description: ownerView ? row.description : (row.description ? row.description.replace(/password|otp|pin/gi, '***') : ''),
      anon_id: row.anon_id ? row.anon_id.slice(0,12) : null,
      created_at: row.created_at
    };

    res.render('report-thanks', {
      note: null,
      report: masked,
      ownerView: false, // keep false to never show owner-only actions (no delete)
      reportId: id
    });
  });
});


// Admin: view reports (protected)
app.get('/admin/reports', requireLogin, (req, res) => {
  db.all(`SELECT * FROM reports ORDER BY created_at DESC`, (err, rows) => {
    if (err) {
      console.error('Admin reports error:', err.message);
      return res.status(500).send('Error loading reports');
    }
    res.render('admin-reports', { reports: rows });
  });
});

// ---------- QR scan route (keep last so it doesn't catch admin paths) ----------
app.get('/:qrid', async (req, res) => {
  const qrId = req.params.qrid;
  const userAgent = req.headers['user-agent'] || '';
  const datetime = new Date().toISOString();

  // Ensure persistent anonymous ID via cookie (not personally identifying)
  const anonId = req.cookies.anonId || uuidv4();
  if (!req.cookies.anonId) {
    // Not httpOnly so we can display the partial value on page; set httpOnly if you prefer.
    res.cookie('anonId', anonId, { sameSite: 'Lax', maxAge: 31536000000 });
  }

  // Client IPs
  const { ipv4, ipv6 } = extractIPs(req);

  // City/Country/ISP (awareness only)
  const location = await ipToLocation(ipv4, ipv6);

  // Insert scan row
  db.run(
    `INSERT INTO scans (qr_id, user_agent, datetime, ipv4, ipv6, anon_id)
     VALUES (?, ?, ?, ?, ?, ?)`,
    [qrId, userAgent, datetime, ipv4, ipv6, anonId],
    (err) => {
      if (err) {
        console.error('DB insert error:', err.message);
        return res.status(500).send('Database error');
      }

      // Count scans for this QR ID
      db.get(`SELECT COUNT(*) AS count FROM scans WHERE qr_id = ?`, [qrId], (err2, row) => {
        if (err2) {
          console.error('Count error:', err2.message);
          return res.status(500).send('Count retrieval error');
        }

        // Fetch the most recent provided name for this anon ID (if any)
        db.get(
          `SELECT user_name FROM scans
           WHERE anon_id = ? AND user_name IS NOT NULL
           ORDER BY id DESC LIMIT 1`,
          [anonId],
          (err3, named) => {
            if (err3) return res.status(500).send('Error loading name');

            res.render('index', {
              qrId,
              count: row?.count || 1,
              datetime: new Date().toLocaleString('en-MY', { timeZone: 'Asia/Kuala_Lumpur' }),
              location,                     // e.g., "Kuala Lumpur, Malaysia (Maxis ISP)"
              anonId,                       // full anon id (we’ll display a short part)
              userName: named?.user_name || null,
            });
          }
        );
      });
    }
  );
});

// ---------- Start ----------
app.listen(PORT, () => {
  console.log(`🚀 Server running at http://localhost:${PORT}`);
});
