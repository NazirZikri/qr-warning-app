const express = require('express');
const db = require('./db');
const path = require('path');
const session = require('express-session');
const bcrypt = require('bcrypt');

const app = express();
const PORT = 3000;

// Middleware
app.use(express.json());
app.use(express.static('public'));
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use(session({
  secret: 'admin123', // 🔒 Replace with strong secret in production
  resave: false,
  saveUninitialized: true,
}));

// 🧠 Extract both IPv4 and IPv6 from request
function extractIPs(req) {
  let rawIp =
    req.headers['x-forwarded-for']?.split(',')[0] ||
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

// 🔐 Admin hashed password (bcrypt hash of 'admin123')
const ADMIN_HASHED_PASSWORD = '$2b$10$zOC/SjFId1hCQgIfK0GowuF8NaQlPfq7g2JuL7CIp6PCxZtxz7EdK';

// 🔒 Protect /admin routes
function requireLogin(req, res, next) {
  if (req.session && req.session.loggedIn) {
    return next();
  }
  res.redirect('/admin/login');
}

// 🔐 Admin login routes
app.get('/admin/login', (req, res) => {
  res.render('login', { error: null });
});

app.post('/admin/login', express.urlencoded({ extended: true }), async (req, res) => {
  const { password } = req.body;
  const match = await bcrypt.compare(password, ADMIN_HASHED_PASSWORD);
  if (match) {
    req.session.loggedIn = true;
    res.redirect('/admin/scans');
  } else {
    res.render('login', { error: 'Invalid password' });
  }
});

app.get('/admin/logout', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/admin/login');
  });
});

app.get('/admin/scans', requireLogin, (req, res) => {
  db.all(`SELECT * FROM scans ORDER BY datetime DESC`, (err, rows) => {
    if (err) {
      console.error('Admin error:', err.message);
      return res.status(500).send('Error loading scans');
    }

    res.render('admin', { scans: rows });
  });
});

// 📲 QR scan route
app.get('/:qrid', (req, res) => {
  const qrId = req.params.qrid;
  const userAgent = req.headers['user-agent'];
  const datetime = new Date().toISOString();
  const { ipv4, ipv6 } = extractIPs(req);

  db.run(
    `INSERT INTO scans (qr_id, user_agent, datetime, ipv4, ipv6) VALUES (?, ?, ?, ?, ?)`,
    [qrId, userAgent, datetime, ipv4, ipv6],
    function (err) {
      if (err) {
        console.error('DB insert error:', err.message);
        return res.status(500).send('Database error');
      }

      db.get(
        `SELECT COUNT(*) as count FROM scans WHERE qr_id = ?`,
        [qrId],
        (err, row) => {
          if (err) {
            console.error('Count error:', err.message);
            return res.status(500).send('Count retrieval error');
          }

          res.render('index', {
            qrId,
            count: row.count,
            datetime: new Date().toLocaleString('en-MY', {
              timeZone: 'Asia/Kuala_Lumpur',
            }),
          });
        }
      );
    }
  );
});

// 🟢 Start server
app.listen(PORT, () => {
  console.log(`🚀 Server running at http://localhost:${PORT}`);
});
